package twitter

import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const apiResource = "https://api.twitter.com"

// Client is twitter client.
type Client struct {
	consumerKey      string
	consumerSecret   string
	oauthToken       string
	oauthTokenSecret string
	client           *http.Client
}

// NewTwitterClient returns new twitter authentication.
func NewTwitterClient(client *http.Client, consumerKey, consumerSecret, oauthToken, oauthTokenSecret string) *Client {
	return &Client{
		consumerKey:      consumerKey,
		consumerSecret:   consumerSecret,
		oauthToken:       oauthToken,
		oauthTokenSecret: oauthTokenSecret,
		client:           client,
	}
}

// Call calls arbitary twitter api.
func (t *Client) Call(method, path string, params url.Values, obj interface{}) error {
	res, err := t.call(method, path, params, true)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if obj != nil {
		if err := json.NewDecoder(res.Body).Decode(&obj); err != nil {
			return err
		}
	}
	return nil
}

func (t *Client) call(method, path string, params url.Values, isAPI bool) (*http.Response, error) {
	var r io.Reader
	reqPath := path
	if params != nil {
		if isAPI {
			reqPath = path + "?" + params.Encode()
		} else {
			r = strings.NewReader(params.Encode())
		}
	}

	request, err := http.NewRequest(method, reqPath, r)
	if err != nil {
		return nil, err
	}
	if request.Body != nil {
		defer request.Body.Close()
	}

	header := t.header(method, path, params)
	request.Header.Set("Authorization", header)
	res, err := t.client.Do(request)
	if err != nil {
		return nil, err
	} else if 400 <= res.StatusCode {
		b, _ := ioutil.ReadAll(res.Body)
		return nil, errors.New(string(b))
	}
	return res, nil
}

// VerifyUser verfies user, then set user information to argument interface.
func (t *Client) VerifyUser(user interface{}, params url.Values) error {
	return t.Call(http.MethodGet, apiResource+"/1.1/account/verify_credentials.json", params, user)
}

// Tweet tweets on timeline.
func (t *Client) Tweet(params url.Values) error {
	return t.Call(http.MethodPost, apiResource+"/1.1/statuses/update.json", params, nil)
}

// Home gets home timeline.
func (t *Client) Home(timeline interface{}, params url.Values) error {
	return t.Call(http.MethodGet, apiResource+"/1.1/statuses/home_timeline.json", params, timeline)
}
