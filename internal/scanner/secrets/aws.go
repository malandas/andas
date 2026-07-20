package secrets

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// An AWS access key ID (AKIA…) cannot be validated alone — it needs its paired
// secret access key. So when we find an access key ID, we look for a nearby
// secret in the same file and, if found, prove the pair by making a signed,
// read-only STS GetCallerIdentity call (the AWS equivalent of "who am I").

// reAWSSecret matches a candidate 40-char base64 AWS secret access key. It is
// intentionally only used *near* a detected access key ID, since on its own the
// pattern is far too generic to report.
var reAWSSecret = regexp.MustCompile(`[A-Za-z0-9/+]{40}`)

// findAWSSecret returns the first plausible secret key in the given text that
// isn't the access key ID itself.
func findAWSSecret(text, accessKeyID string) string {
	for _, cand := range reAWSSecret.FindAllString(text, -1) {
		if cand != accessKeyID {
			return cand
		}
	}
	return ""
}

// awsValidateSTS signs a GetCallerIdentity request with SigV4 and reports
// whether the credential pair is live, plus its blast radius: the identity ARN
// it authenticates as and whether that identity is dangerously privileged.
func awsValidateSTS(accessKeyID, secretKey string, timeoutS int) Result {
	if timeoutS <= 0 {
		timeoutS = 8
	}
	const (
		region  = "us-east-1"
		service = "sts"
		host    = "sts.amazonaws.com"
		payload = "Action=GetCallerIdentity&Version=2011-06-15"
	)
	ctype := "application/x-www-form-urlencoded; charset=utf-8"

	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	payloadHash := sha256Hex(payload)
	canonicalHeaders := "content-type:" + ctype + "\nhost:" + host + "\nx-amz-date:" + amzDate + "\n"
	signedHeaders := "content-type;host;x-amz-date"
	canonicalRequest := strings.Join([]string{
		"POST", "/", "", canonicalHeaders, signedHeaders, payloadHash,
	}, "\n")

	scope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonicalRequest),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	auth := "AWS4-HMAC-SHA256 Credential=" + accessKeyID + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature

	req, err := http.NewRequest("POST", "https://"+host+"/", strings.NewReader(payload))
	if err != nil {
		return Result{Note: "request build failed"}
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Authorization", auth)

	client := &http.Client{Timeout: time.Duration(timeoutS) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Result{Note: "network error: " + err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case 200:
		arn := awsArn(body)
		r := Result{Live: true, Note: "AWS accepted the key pair (STS GetCallerIdentity) — LIVE", Identity: arn, Privileged: awsPrivileged(arn)}
		if acct := awsAccount(body); acct != "" {
			r.Scopes = []string{"account " + acct}
		}
		return r
	case 403:
		return Result{Note: "AWS rejected the key pair — invalid, expired, or unpaired"}
	default:
		return Result{Note: "inconclusive AWS response"}
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
