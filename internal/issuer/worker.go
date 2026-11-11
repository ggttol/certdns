// Package issuer obtains certificates via ACME DNS-01 across multiple Alibaba
// Cloud DNS accounts (China & International), runs the job queue and renewal
// scheduler, sends webhook notifications, and exports the management TLS cert.
package issuer

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"certdns/internal/alidns"
	"certdns/internal/store"
	"certdns/internal/webhook"
)

const RenewBefore = 30 * 24 * time.Hour

// Manager owns certificate files, multi-account DNS resolution, and background jobs.
type Manager struct {
	Store     *store.Store
	DataDir   string
	TLSDir    string
	Hostname  string
	Resolvers []string
	Webhook   *webhook.Sender
	// DirectoryURL and NewDNS can be replaced in tests.
	DirectoryURL func(staging bool) string
	NewDNS       func(alidns.Credentials) *alidns.Client

	wake         chan struct{}
	tlsMu        sync.Mutex
	pollInterval time.Duration
}

// New creates a Manager configured with default DNS resolvers, ACME directories, and SSRF-safe Webhook sender.
func New(s *store.Store, dataDir, tlsDir, hostname string) *Manager {
	return &Manager{
		Store:     s,
		DataDir:   dataDir,
		TLSDir:    tlsDir,
		Hostname:  hostname,
		Resolvers: []string{"223.5.5.5:53", "119.29.29.29:53", "1.1.1.1:53"},
		Webhook:   webhook.NewSender(hostname),
		DirectoryURL: func(staging bool) string {
			if staging {
				return StagingURL
			}
			return ProductionURL
		},
		NewDNS: alidns.New,
		wake:   make(chan struct{}, 1),
	}
}

// Wake nudges the worker to look for queued jobs immediately.
func (m *Manager) Wake() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

type jobLog struct {
	m  *Manager
	id string
}

var privateKeyRE = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

func redact(s string) string {
	return privateKeyRE.ReplaceAllString(s, "[已隐藏私钥]")
}

func (l *jobLog) Write(p []byte) (int, error) {
	clean := strings.TrimRight(redact(string(p)), "\r\n")
	if clean == "" {
		return len(p), nil
	}
	ts := time.Now().Format("15:04:05 ")
	lines := strings.Split(clean, "\n")
	var dbBuf, outBuf strings.Builder
	shortID := l.id
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		dbBuf.WriteString(ts)
		dbBuf.WriteString(line)
		dbBuf.WriteByte('\n')

		outBuf.WriteString("[job ")
		outBuf.WriteString(shortID)
		outBuf.WriteString("] ")
		outBuf.WriteString(ts)
		outBuf.WriteString(line)
		outBuf.WriteByte('\n')
	}

	logCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = l.m.Store.AppendJobOutput(logCtx, l.id, dbBuf.String())
	cancel()

	_, _ = os.Stdout.WriteString(outBuf.String())
	return len(p), nil
}

// RunWorker processes queued jobs one at a time until ctx is cancelled.
// On host shutdown (ctx.Err() != nil), an interrupted active job is requeued without
// marking the certificate as error or firing a false failure webhook.
func (m *Manager) RunWorker(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if err := m.Store.RecoverInterrupted(ctx); err != nil {
		log.Printf("recover interrupted jobs: %v", err)
	}
	m.CleanupStale(ctx)

	for {
		if ctx.Err() != nil {
			return
		}
		job, err := m.Store.ClaimJob(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("claim job: %v", err)
		}
		if job == nil {
			select {
			case <-ctx.Done():
				return
			case <-m.wake:
			case <-time.After(5 * time.Second):
			}
			continue
		}

		jobCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		info, err := m.process(jobCtx, job)
		jobTimedOut := errors.Is(jobCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
		cancel()

		if err != nil && ctx.Err() != nil {
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 8*time.Second)
			if rerr := m.Store.RequeueJob(shutCtx, job, "服务重启，任务已重新入队等待续跑"); rerr != nil {
				log.Printf("requeue interrupted job %s: %v", job.ID, rerr)
			}
			m.CleanupStale(shutCtx)
			shutCancel()
			return
		}

		postCtx, postCancel := context.WithTimeout(context.Background(), 15*time.Second)
		failure := ""
		if err != nil {
			failure = redact(err.Error())
			if jobTimedOut {
				failure = "任务执行超时（30 分钟）: " + failure
			}
		}
		if ferr := m.Store.FinishJob(postCtx, job, info, failure); ferr != nil {
			log.Printf("finish job %s: %v", job.ID, ferr)
		}
		if cert, cerr := m.Store.Certificate(postCtx, job.CertificateID); cerr == nil {
			if info != nil {
				m.NotifyWebhook(postCtx, "证书签发/续期成功",
					fmt.Sprintf("域名: %s\n到期时间: %s", strings.Join(cert.Domains, ", "), info.NotAfter))
			} else {
				m.NotifyWebhook(postCtx, "证书签发/续期失败",
					fmt.Sprintf("域名: %s\n原因: %s", strings.Join(cert.Domains, ", "), failure))
			}
		}
		if info != nil {
			if serr := m.SyncTLS(postCtx); serr != nil {
				log.Printf("sync tls: %v", serr)
			}
		}
		m.CleanupStale(postCtx)
		postCancel()
	}
}

// NotifyWebhook sends a notification to the configured webhook URL if set.
func (m *Manager) NotifyWebhook(ctx context.Context, title, body string) {
	url, err := m.Store.Setting(ctx, "webhook_url")
	if err != nil || strings.TrimSpace(url) == "" {
		return
	}
	sender := m.Webhook
	if sender == nil {
		sender = webhook.NewSender(m.Hostname)
	}
	if err := sender.Send(ctx, url, title, body); err != nil {
		log.Printf("webhook send failed: %v", err)
	}
}

// CleanupStale removes challenge records left behind by interrupted jobs.
func (m *Manager) CleanupStale(ctx context.Context) {
	pending, err := m.Store.Challenges(ctx)
	if err != nil || len(pending) == 0 {
		return
	}
	for _, ch := range pending {
		if ctx.Err() != nil {
			return
		}
		if err := m.removeChallenge(ctx, ch); err != nil {
			log.Printf("stale challenge cleanup failed for record %s: %s", ch.RecordID, alidns.Hint(err))
		}
	}
}

// QueueDue queues renewals for ACME certificates expiring within RenewBefore.
func (m *Manager) QueueDue(ctx context.Context) (int, error) {
	certs, err := m.Store.Certificates(ctx)
	if err != nil {
		return 0, err
	}
	queued := 0
	for _, c := range certs {
		if !c.AutoRenew || c.Source == "upload" || c.NotAfter == "" {
			continue
		}
		notAfter, err := time.Parse(time.RFC3339, c.NotAfter)
		if err != nil || time.Until(notAfter) > RenewBefore {
			continue
		}
		if _, err := m.Store.QueueJob(ctx, c.ID, "renew", "auto"); err == nil {
			queued++
		} else if !errors.Is(err, store.ErrActiveJob) {
			return queued, err
		}
	}
	if queued > 0 {
		m.Wake()
	}
	return queued, nil
}

// RunScheduler checks for due renewals shortly after start and then every 6 hours.
func (m *Manager) RunScheduler(ctx context.Context) {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if n, err := m.QueueDue(ctx); err != nil {
				if ctx.Err() == nil {
					log.Printf("renewal scan: %v", err)
				}
			} else if n > 0 {
				log.Printf("renewal scan queued %d job(s)", n)
			}
			timer.Reset(6 * time.Hour)
		}
	}
}
