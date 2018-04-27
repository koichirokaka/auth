package twitter

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const oauthTokenResource = "https://api.twitter.com/oauth/authenticate?oauth_token=%s"

// LoginURL create twitter login url.
func (t *Client) LoginURL(callbackURL string) (string, error) {
	params := url.Values{}
	params.Set("oauth_callback", callbackURL)
	if err := t.RequestToken(params); err != nil {
		return "", err
	}

	return fmt.Sprintf(oauthTokenResource, t.oauthToken), nil
}

// RequestToken requests token to twitter authentication.
func (t *Client) RequestToken(params url.Values) error {
	path := apiResource + "/oauth/request_token"

	res, err := t.call(http.MethodPost, path, params, false)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	b, _ := ioutil.ReadAll(res.Body)
	uv, err := url.ParseQuery(string(b))
	if err != nil {
		return err
	}

	// verify callback
	verify := uv.Get("oauth_callback_confirmed")
	if verify != "true" {
		return errors.New("callback is not verified")
	}

	t.oauthToken, t.oauthTokenSecret = uv.Get("oauth_token"), uv.Get("oauth_token_secret")
	return nil
}

// AccessToken requests access token.
func (t *Client) AccessToken(params url.Values) (oauthToken, oauthTokenSecret string, err error) {
	path := apiResource + "/oauth/access_token"

	res, err := t.call(http.MethodPost, path, params, false)
	if err != nil {
		return
	}
	defer res.Body.Close()

	b, _ := ioutil.ReadAll(res.Body)
	uv, err := url.ParseQuery(string(b))
	if err != nil {
		return
	}

	t.oauthToken, t.oauthTokenSecret = uv.Get("oauth_token"), uv.Get("oauth_token_secret")
	return
}

// SetToken sets oauth token and oauth secret to twitter authentication.
func (t *Client) SetToken(oauthToken, oauthTokenSecret string) {
	t.oauthToken = oauthToken
	t.oauthTokenSecret = oauthTokenSecret
}

func (t *Client) header(method, path string, params url.Values) string {
	header := OAuthHeader(method, path, t.consumerKey, t.consumerSecret, t.oauthToken, t.oauthTokenSecret, params)
	return header
}

// OAuthHeader creates oauth header for twitter
func OAuthHeader(method, path, consumerKey, consumerSecret, accessToken, tokenSecret string, params url.Values) string {
	nonce := RandSeq(32)
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)

	elems := make([]string, 0, 6+len(params))
	elems = append(elems, "oauth_consumer_key="+consumerKey)
	elems = append(elems, "oauth_nonce="+nonce)
	elems = append(elems, "oauth_signature_method=HMAC-SHA1")
	elems = append(elems, "oauth_timestamp="+timestamp)
	elems = append(elems, "oauth_token="+accessToken)
	elems = append(elems, "oauth_version=1.0")
	for k := range params {
		v := params.Get(k)
		if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
			v = url.QueryEscape(v)
		} else {
			p := &url.URL{Path: v}
			v = p.String()
		}
		elems = append(elems, k+"="+v)
	}

	base := strings.ToUpper(method) + "&" + url.QueryEscape(path)
	sort.Strings(elems)
	q := url.QueryEscape(strings.Join(elems, "&"))

	baseString := base + "&" + q
	signingKey := consumerSecret + "&" + tokenSecret

	signature := generateSignature(baseString, signingKey)

	ckh := "oauth_consumer_key=\"" + consumerKey + "\""
	nh := "oauth_nonce=\"" + nonce + "\""
	sh := "oauth_signature=\"" + signature + "\""
	smh := "oauth_signature_method=\"HMAC-SHA1\""
	tsh := "oauth_timestamp=\"" + timestamp + "\""
	th := "oauth_token=\"" + accessToken + "\""
	vh := "oauth_version=\"1.0\""

	value := strings.Join([]string{ckh, nh, sh, smh, tsh, th, vh}, ", ")
	return "OAuth " + value
}

func generateSignature(baseString, signingKey string) string {
	p := []byte(baseString)
	hash := hmac.New(sha1.New, []byte(signingKey))
	hash.Write(p)
	sum := hash.Sum(nil)
	return url.QueryEscape(base64.StdEncoding.EncodeToString(sum))
}
