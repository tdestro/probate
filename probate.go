package main

import (
	"net/http/cookiejar"
	"io/ioutil"
	"net/http"
	"log"
	"fmt"
	"strings"
	"net/url"
	"bytes"
	"strconv"
	"golang.org/x/net/html"
	"errors"
	"encoding/csv"
	"os"
     "googlemaps.github.io/maps"
	"golang.org/x/net/context"
)

const (
	outputFile = "output.csv"
	outputLongLatFile = "outputLongLat.csv"
)


/*
POST /Wills/Login.aspx HTTP/1.1
Host: dcr.alleghenycounty.us
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 680
Referer: https://dcr.alleghenycounty.us/Wills/Login.aspx
Connection: keep-alive
Upgrade-Insecure-Requests: 1

__LASTFOCUS=&__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwULLTE3NDkzNzE5OTUPZBYCAgMPZBYGAgEPZBYKAgcPDxYCHgRUZXh0ZWRkAhEPDxYCHgdWaXNpYmxlZ2RkAiUPDxYCHgtOYXZpZ2F0ZVVybAULfi9ob21lLmFzcHhkZAInDw8WAh8CBQt%2BL2hvbWUuYXNweGRkAisPDxYCHwFoZGQCAw8PFgIfAGVkZAIZDw8WAh8ABQ1SZWdpc3RlciBIZXJlZGRkJuYkbov4WLOiEbD6EKizSvBn9RyyHbq6vAw6fc98qh0%3D&__VIEWSTATEGENERATOR=CCD01088&__EVENTVALIDATION=%2FwEdAAgeQCzYV%2F%2BeMeLJpfO%2FYWtyBS%2ByUdCopfSRCfYD8DzyuEp79jt31IG59sYSnbDk4seoV7n24SKj5sCn%2Ffdhk5Hdop4oRunf14dz2Zt2%2BQKDEDIL9eygnkeVplQpb0EzqUrsNjqq6NOhzBuKQT%2Fyd0p64f0L3QcyOR1Wv8panGnFJhZbUPSPJrJMR7zHuOUZQVyTWfJlSxCjLKjBzKH%2B30oX&tbUserId=archangel689&tbPassword=Password1&btnLogin=Login
 */

func RunUntilNextStartTagNamed(tt *html.TokenType, z *html.Tokenizer, t *html.Token, tag string) (error) {

	// run until next start tag named and leave us at the contents.
	for {
		*tt = z.Next()
		if *tt == html.StartTagToken && z.Token().Data == tag {
			*tt = z.Next()

			if *tt == html.ErrorToken {
				return errors.New("ErrorToken")
			}

			*t = z.Token()
			break;
		} else if *tt == html.ErrorToken {
			return errors.New("ErrorToken")
		}
	}

	return nil
}

func keyValueExists(n html.Token, key string, value string) (bool) {
	for _, attr := range n.Attr {
		if attr.Key == key && strings.Contains(attr.Val, value) {
			return true
		}
	}
	return false
}

func shouldRedirect(req *http.Request, via []*http.Request) error {
	// Copy User-Agent and Cookie from the original request
	original := via[0]
	req.Header.Set("User-Agent", original.UserAgent())
	return nil
}

func GetInnerSubstring(str string, prefix string, suffix string) string {
	var beginIndex, endIndex int
	beginIndex = strings.Index(str, prefix)
	if beginIndex == -1 {
		beginIndex = 0
		endIndex = 0
	} else if len(prefix) == 0 {
		beginIndex = 0
		endIndex = strings.Index(str, suffix)
		if endIndex == -1 || len(suffix) == 0 {
			endIndex = len(str)
		}
	} else {
		beginIndex += len(prefix)
		endIndex = strings.Index(str[beginIndex:], suffix)
		if endIndex == -1 {
			if strings.Index(str, suffix) < beginIndex {
				endIndex = beginIndex
			} else {
				endIndex = len(str)
			}
		} else {
			if len(suffix) == 0 {
				endIndex = len(str)
			} else {
				endIndex += beginIndex
			}
		}
	}

	return str[beginIndex:endIndex]
}

func before(value string, a string) string {
	// Get substring before a string.
	pos := strings.Index(value, a)
	if pos == -1 {
		return ""
	}
	return value[0:pos]
}

/*

GET /Wills/Login.aspx HTTP/1.1
Host: dcr.alleghenycounty.us
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

*/

func main() {

	fmt.Println(os.Args[1] + " to " + os.Args[2])

	cookieJar, _ := cookiejar.New(nil)

	//proxyUrl, err := url.Parse(Proxy)
	//transport := &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	//client := &http.Client{Transport: transport, Jar: cookieJar, }

	client := &http.Client{
		Jar: cookieJar,
	}

	client.CheckRedirect = shouldRedirect

	req, _ := http.NewRequest("GET", "https://dcr.alleghenycounty.us/Wills/Login.aspx", nil) // <-- URL-encoded payload
	req.Header.Add("Host", "dcr.alleghenycounty.us")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.36")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Add("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(resp.Status)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	bodyString := string(body)

	viewstate := GetInnerSubstring(bodyString, `id="__VIEWSTATE" value="`, `" />`)
	viewstategen := GetInnerSubstring(bodyString, `id="__VIEWSTATEGENERATOR" value="`, `" />`)
	eventvalidation := GetInnerSubstring(bodyString, `id="__EVENTVALIDATION" value="`, `" />`)

	/*
		__LASTFOCUS
		__EVENTTARGET
		__EVENTARGUMENT
		__VIEWSTATE	/wEPDwULLTE3NDkzNzE5OTUPZBYCAgMPZBYGAgEPZBYKAgcPDxYCHgRUZXh0ZWRkAhEPDxYCHgdWaXNpYmxlZ2RkAiUPDxYCHgtOYXZpZ2F0ZVVybAULfi9ob21lLmFzcHhkZAInDw8WAh8CBQt+L2hvbWUuYXNweGRkAisPDxYCHwFoZGQCAw8PFgIfAGVkZAIZDw8WAh8ABQ1SZWdpc3RlciBIZXJlZGRkJuYkbov4WLOiEbD6EKizSvBn9RyyHbq6vAw6fc98qh0=
			__VIEWSTATEGENERATOR	CCD01088
		__EVENTVALIDATION	/wEdAAgeQCzYV/+eMeLJpfO/YWtyBS+yUdCopfSRCfYD8DzyuEp79jt31IG59sYSnbDk4seoV7n24SKj5sCn/fdhk5Hdop4oRunf14dz2Zt2+QKDEDIL9eygnkeVplQpb0EzqUrsNjqq6NOhzBuKQT/yd0p64f0L3QcyOR1Wv8panGnFJhZbUPSPJrJMR7zHuOUZQVyTWfJlSxCjLKjBzKH+30oX
		tbUserId	archangel689
		tbPassword	Password1
		btnLogin	Login
		*/

	data := url.Values{}
	data.Add("__LASTFOCUS", "")
	data.Add("__EVENTTARGET", "")
	data.Add("__EVENTARGUMENT", "")
	data.Add("__VIEWSTATE", viewstate)
	data.Add("__VIEWSTATEGENERATOR", viewstategen)
	data.Add("__EVENTVALIDATION", eventvalidation)
	data.Add("tbUserId", "archangel689")
	data.Add("tbPassword", "Password1")
	data.Add("btnLogin", "Login")
	encData := data.Encode()

	req, _ = http.NewRequest("POST", "https://dcr.alleghenycounty.us/Wills/Login.aspx", bytes.NewBufferString(encData)) // <-- URL-encoded payload
	/*
POST /Wills/Login.aspx HTTP/1.1
Host: dcr.alleghenycounty.us
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,;q=0.8
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 680
Referer: https://dcr.alleghenycounty.us/Wills/Login.aspx
Cookie: ASP.NET_SessionId=ww3tgjoxsivtqagkqvznvqzm
Connection: keep-alive
	Upgrade-Insecure-Requests: 1

	 */

	req.Header.Add("Host", "dcr.alleghenycounty.us")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.36")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Add("Accept-Language", "en-US,en;q=0.5")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(encData)))
	req.Header.Add("Referer", "https://dcr.alleghenycounty.us/Wills/Login.aspx")
	_, err = client.Do(req)

	if err != nil {
		log.Fatal(err)
	}

	/*body, err := ioutil.ReadAll(resp.Body);

	if err != nil {
		log.Fatal(err)
	}*/

	//	fmt.Println(string(body))

	req, _ = http.NewRequest("GET", "https://dcr.alleghenycounty.us/Wills/PUBLICSEARCH/DateSearch.aspx", nil) // <-- URL-encoded payload
	req.Header.Add("Host", "dcr.alleghenycounty.us")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.36")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Add("Accept-Language", "en-US,en;q=0.5")

	resp, err = client.Do(req)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(resp.Status)

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	bodyString = string(body)

	viewstate = GetInnerSubstring(bodyString, `id="__VIEWSTATE" value="`, `" />`)
	viewstategen = GetInnerSubstring(bodyString, `id="__VIEWSTATEGENERATOR" value="`, `" />`)
	eventvalidation = GetInnerSubstring(bodyString, `id="__EVENTVALIDATION" value="`, `" />`)

	/*


	__EVENTTARGET	btnSearch
	__LASTFOCUS
	__EVENTARGUMENT
	__VIEWSTATE	/wEPDwUJMjkzOTg5NTI5D2QWAgIED2QWBAIBD2QWBgIHDw8WAh4EVGV4dAUgQVJDSEFOR0VMNjg5PGJyIC8+REVTVFJPIEFOVEhPTllkZAIlDw8WAh4LTmF2aWdhdGVVcmwFC34vaG9tZS5hc3B4ZGQCJw8PFgIfAQULfi9ob21lLmFzcHhkZAILD2QWAgIBD2QWAmYPZBYCAgEPZBYCAgEPZBYCZg9kFgJmD2QWAgIBD2QWAgICD2QWAmYPZBYCAgEPEA8WBh4NRGF0YVRleHRGaWVsZAULREVTQ1JJUFRJT04eDkRhdGFWYWx1ZUZpZWxkBQRDT0RFHgtfIURhdGFCb3VuZGdkEBUiF1BsZWFzZSBTZWxlY3QgQ2FzZSBUeXBlDkFsbCBDYXNlIFR5cGVzBUFEVUxUBkNBVkVBVB1DTEFJTSBBR0FJTlNUIERFQ0VERU5UJ1MgRVNULgtDT1JQT1JBVElPThFERUNFREVOVCdTIEVTVEFURR5ERUNFREVOVCdTIEVTVEFURSAoQ09OVkVSU0lPTikKRElTQ0xBSU1FUhJFWEVDVVRPUiBPRiBSRUNPUkQeRVhFTVBMSUZJQ0FUSU9OIE9GIFJFQyAoSU4gU1QpGUxFVFRFUlMgT0YgQURNSU5JU1RSQVRJT04cTUlTQy4gREVDRURFTlQnUyBFU1RBVEUgUEVULhZOT04tUFJPRklUIENPUlBPUkFUSU9ODVBFVElUSU9OIDM1NDYVUEVUSVRJT04gRk9SIENJVEFUSU9OFVBFVElUSU9OIEZPUiBDSVRBVElPThZQRVRJVElPTiBUTyBBRE1JVCBDT1BZGVBFVElUSU9OIFRPIEdSQU5UIExFVFRFUlMRUE9XRVIgT0YgQVRUT1JORVkUUFJFU1VNUFRJT04gT0YgREVBVEgdUFJPQkFURSBBVVRIIFJFQyAoTyBPRiBTVEFURSkSUFJPQkFURSBOTyBMRVRURVJTDFBST0JBVEUgV0lMTBRQUk9CQVRFIFdJVEggTEVUVEVSUw5QUk9PRiBPRiBERUFUSAVUUlVTVBBUUlVTVCAtIENFTUVURVJZEVRSVVNUIC0gSU5TVVJBTkNFE1RSVVNUIC0gSU5URVIgVklWT1MOVFJVU1QgLSBMSVZJTkcVVFJVU1QgLSBTUEVDSUFMIE5FRURTD1RSVVNUIEFHUkVFTUVOVBRUUlVTVCBVTkRFUiBUSEUgV0lMTBUiAA5BbGwgQ2FzZSBUeXBlcwIwNQIxNQJEQwIwOAIwMQI5OQJERAIxNAIxNgIxMwJETQJDTgJQRAIxOAJBQwJUQQJETAJBQQJEUgIxNwIxMAIxMgIxMQJEUAIwMgJUQwJUSQJUVAJUTAJUTgJURwIxORQrAyJnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnFgECAWRk9buvEIGNy6Co7ngU6U7i3GAMscrFR4QHql3tOcICFCg=
	__VIEWSTATEGENERATOR	4DC755B2
	__EVENTVALIDATION	/wEdACfKJbaHGsb3S5lLp4kp9hB2eKoqdLY1DpPECxREJPJxA9P9MCZiCJUHGUieiWIdrb+usslRODGwgSvrFiCZT3ohafExYZZEAHIB96jHa6rayUCQolLQbFyFjxiq9sbUEgQ5CP8cIcdiITRUOka/V6VjjSVH6ROMTrsjrYH/k1aSrETGWx989qPVSEhlpLofoolZi16S5dybNvqARdBrUX/bXtpRWY77HOOLjS5a1YSYlZiWaW/gSRQos0iXa3NzSSTxmiSp/3cygnqTX0wJHr9RgZD25mTyUbhumt+4gDyj4jaMfXeWiL4qL8MlvbDeqzF/HBZhpYublZSYx18urjT7oBFulTW8GkFFEFioCWe36fPBsIl6Kp73XbxxbCWoR+JyrYHFdopujvZzowULVAf2LV6XIro7+pGQ5lgVUTpsJN6J9AK0/hABPUnAZnO1DTzAJwxk2lZSJS1rjaCO9gDvfrMF/JU9EB7OPyJ0RS6Mre5Gh5lCWpAHQow3X368GcGJy96gY8cYnvZEZiHcRhea+MiFCQH7+y30ry7Wqga0RBIIrdmbuQxhcpdYpWhGELwaLTP6TWmpteVKe01lGzEEA1iedr6shAPiDkth7t9KUHdTOqYzHLRWZ3+cgOs330dk2exg6v6WUobYc8VoLo3UGsj8qVhwxHDiM4UYiPBKgqEAUlJ/mnAkzs4W1kDg9W5dRrEMuAkxqF/AMy+5lVe4faHsUcK58g5EpA7gc3FWwya07kREScltbWMSJol34NhTf5PJufnU1kMTcpoEI9CRjtTdVzRZn7DFyWrI8V/OY1vU4E8k9Ng4WJ4gLGyHIHe/gtptsEIADOnaQCNEoaIGQhlzO6EuwjI+gygD67d0LA==
	tbBeginDate	9/13/2017
	tbEndDate	10/13/2017
	ddlCaseType	11
	btnSearch	Search

	*/

	data = url.Values{}
	data.Add("__EVENTTARGET", "btnSearch")
	data.Add("__LASTFOCUS", "")
	data.Add("__EVENTARGUMENT", "")
	data.Add("__VIEWSTATE", viewstate)
	data.Add("__VIEWSTATEGENERATOR", viewstategen)
	data.Add("__EVENTVALIDATION", eventvalidation)
	data.Add("tbBeginDate", os.Args[1])
	data.Add("tbEndDate", os.Args[2])
	data.Add("ddlCaseType", "11")
	data.Add("btnSearch", "Search")
	encData = data.Encode()

	req, _ = http.NewRequest("POST", "https://dcr.alleghenycounty.us/Wills/PUBLICSEARCH/DateSearch.aspx", bytes.NewBufferString(encData)) // <-- URL-encoded payload
	/*
	POST /Wills/PUBLICSEARCH/DateSearch.aspx HTTP/1.1
	Host: dcr.alleghenycounty.us
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:56.0) Gecko/20100101 Firefox/56.0
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,;q=0.8
		Accept-Language: en-US,en;q=0.5
		Accept-Encoding: gzip, deflate, br
		Content-Type: application/x-www-form-urlencoded
		Content-Length: 2628
	Referer: https://dcr.alleghenycounty.us/Wills/PUBLICSEARCH/DateSearch.aspx
	Cookie: ASP.NET_SessionId=ww3tgjoxsivtqagkqvznvqzm
	Connection: keep-alive
		Upgrade-Insecure-Requests: 1
		 */

	req.Header.Add("Host", "dcr.alleghenycounty.us")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.36")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Add("Accept-Language", "en-US,en;q=0.5")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(encData)))
	req.Header.Add("Referer", "https://dcr.alleghenycounty.us/Wills/PUBLICSEARCH/DateSearch.aspx")

	var caseNos []string

nextpage:
	resp, err = client.Do(req)

	if err != nil {
		log.Fatal(err)
	}

	body, err = ioutil.ReadAll(resp.Body);
	if err != nil {
		log.Fatal(err)
	}

	bodyString = string(body)
	//fmt.Println(string(body))

	/*GET /Wills/PUBLICSEARCH/InterimPage.aspx?CaseNo=021705316 HTTP/1.1
Host: dcr.alleghenycounty.us
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*;q=0.8
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br
Referer: https://dcr.alleghenycounty.us/Wills/PUBLICSEARCH/DateResult.aspx
Cookie: ASP.NET_SessionId=sqet0b0dyxyffw4zvudocvbu
Connection: keep-alive
	Upgrade-Insecure-Requests: 1


GET /Wills/PUBLICSEARCH/CaseNumberResult.aspx HTTP/1.1
Host: dcr.alleghenycounty.us
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*;q=0.8
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br
Referer: https://dcr.alleghenycounty.us/Wills/PUBLICSEARCH/DateResult.aspx
Cookie: ASP.NET_SessionId=sqet0b0dyxyffw4zvudocvbu
Connection: keep-alive
	Upgrade-Insecure-Requests: 1



	*/

	roughCaseNos := strings.Split(bodyString, `InterimPage.aspx?CaseNo=`)

	roughCaseNos = append(roughCaseNos[:0], roughCaseNos[1:]...)

	for _, el := range roughCaseNos {
		caseNo := before(el, `">`)

		if caseNo != "" {
			caseNos = append(caseNos, caseNo)
		} else {
			fmt.Println("Warning empty case found, skipping.")
		}
	}

	/*__EVENTTARGET	gvResult
__EVENTARGUMENT	Page$Next
__VIEWSTATE	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
__VIEWSTATEGENERATOR	288EFB70
__EVENTVALIDATION	/wEdAAOPOqCP7SzaFgs4JvnEvAuKC3xJkMbqG5b3jFeswsnPyHx8UxPQdZr8hE5p0v0arzhRuB8Mk7U+LhTDIFXvmcJO55SFmSXjhD40TkWKmYYfDw==
	*/

	/*
	POST /Wills/PUBLICSEARCH/DateResult.aspx HTTP/1.1
Host: dcr.alleghenycounty.us
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,;q=0.8
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 12280
Referer: https://dcr.alleghenycounty.us/Wills/PUBLICSEARCH/DateResult.aspx
Cookie: ASP.NET_SessionId=ww3tgjoxsivtqagkqvznvqzm
Connection: keep-alive
	Upgrade-Insecure-Requests: 1


	*/

	/*
		<a href="javascript:__doPostBack('gvResult','Page$Next')" style="color:White;">Next &gt;</a>
	*/

	if strings.Contains(bodyString, "Next &gt;") {
		//fmt.Println("found next")
		viewstate = GetInnerSubstring(bodyString, `id="__VIEWSTATE" value="`, `" />`)
		viewstategen = GetInnerSubstring(bodyString, `id="__VIEWSTATEGENERATOR" value="`, `" />`)
		eventvalidation = GetInnerSubstring(bodyString, `id="__EVENTVALIDATION" value="`, `" />`)

		data = url.Values{}
		data.Add("__EVENTTARGET", "gvResult")
		data.Add("__EVENTARGUMENT", "Page$Next")
		data.Add("__VIEWSTATE", viewstate)
		data.Add("__VIEWSTATEGENERATOR", viewstategen)
		data.Add("__EVENTVALIDATION", eventvalidation)

		encData = data.Encode()

		req, _ = http.NewRequest("POST", "https://dcr.alleghenycounty.us/Wills/PUBLICSEARCH/DateResult.aspx", bytes.NewBufferString(encData)) // <-- URL-encoded payload

		req.Header.Add("Host", "dcr.alleghenycounty.us")
		req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.36")
		req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Add("Accept-Language", "en-US,en;q=0.5")
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("Content-Length", strconv.Itoa(len(encData)))
		req.Header.Add("Referer", "https://dcr.alleghenycounty.us/Wills/PUBLICSEARCH/DateResult.aspx")

		goto nextpage
	}

	fmt.Println("Visiting case pages.")

	var output = [][]string{}


	for _, caseNo := range caseNos {

		caseURL := "https://dcr.alleghenycounty.us/Wills/PUBLICSEARCH/InterimPage.aspx?CaseNo=" + caseNo

		fmt.Println("Visiting: " + caseURL)

		req, _ = http.NewRequest("GET", caseURL, nil) // <-- URL-encoded payload
		req.Header.Add("Host", "dcr.alleghenycounty.us")
		req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.36")
		req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Add("Accept-Language", "en-US,en;q=0.5")
		req.Header.Add("Referer", "https://dcr.alleghenycounty.us/Wills/PUBLICSEARCH/DateResult.aspx")
		resp, err = client.Do(req)

		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(resp.Status)

		z := html.NewTokenizer(resp.Body)

		for {
			tt := z.Next()

			switch {
			case tt == html.ErrorToken:
				// End of the document, we're done
				goto endtraverse
			case tt == html.StartTagToken:
				t := z.Token()

				if (t.Data == "span" || t.Data == "a") && keyValueExists(t, "id", "gvDecedentResult") {
					fmt.Println("Found Span with Decendent id")

					var outputLine = []string{}


					err = RunUntilNextStartTagNamed(&tt, z, &t, "td")
					if err != nil {
						log.Fatal(err)
					}

					//LName	FName	MI	Type	Address

					outputLine = append(outputLine, t.Data)
					fmt.Println(t.Data)

					err = RunUntilNextStartTagNamed(&tt, z, &t, "td")
					if err != nil {
						log.Fatal(err)
					}

					//LName	FName	MI	Type	Address

					outputLine = append(outputLine, t.Data)
					fmt.Println(t.Data)

					err = RunUntilNextStartTagNamed(&tt, z, &t, "td")
					if err != nil {
						log.Fatal(err)
					}

					//LName	FName	MI	Type	Address

					outputLine = append(outputLine, t.Data)
					fmt.Println(t.Data)

					err = RunUntilNextStartTagNamed(&tt, z, &t, "td")
					if err != nil {
						log.Fatal(err)
					}

					//LName	FName	MI	Type	Address

					outputLine = append(outputLine, t.Data)
					fmt.Println(t.Data)

					err = RunUntilNextStartTagNamed(&tt, z, &t, "td")
					if err != nil {
						log.Fatal(err)
					}

					outputLine = append(outputLine, t.Data)
					fmt.Println(t.Data)

					for {
						tt = z.Next()

						switch {
						case tt == html.ErrorToken:
							// End of the document, we're done
							goto endtraverse
						case tt == html.StartTagToken:
							t = z.Token()

							if (t.Data == "span" || t.Data == "a") && keyValueExists(t, "id", "gvMainPartyResult") {
								fmt.Println("Found Span with main party id")


								err = RunUntilNextStartTagNamed(&tt, z, &t, "td")
								if err != nil {
									log.Fatal(err)
								}

								//LName	FName	MI	Type	Address

								outputLine = append(outputLine, t.Data)
								fmt.Println(t.Data)

								err = RunUntilNextStartTagNamed(&tt, z, &t, "td")
								if err != nil {
									log.Fatal(err)
								}

								//LName	FName	MI	Type	Address

								outputLine = append(outputLine, t.Data)
								fmt.Println(t.Data)

								err = RunUntilNextStartTagNamed(&tt, z, &t, "td")
								if err != nil {
									log.Fatal(err)
								}

								//LName	FName	MI	Type	Address

								outputLine = append(outputLine, t.Data)
								fmt.Println(t.Data)

								err = RunUntilNextStartTagNamed(&tt, z, &t, "td")
								if err != nil {
									log.Fatal(err)
								}

								//LName	FName	MI	Type	Address

								outputLine = append(outputLine, t.Data)
								fmt.Println(t.Data)

								err = RunUntilNextStartTagNamed(&tt, z, &t, "td")
								if err != nil {
									log.Fatal(err)
								}

								outputLine = append(outputLine, t.Data)
								fmt.Println(t.Data)

								err = RunUntilNextStartTagNamed(&tt, z, &t, "td")
								if err != nil {
									log.Fatal(err)
								}

								outputLine = append(outputLine, t.Data)
								fmt.Println(t.Data)

								output = append(output, outputLine)
								goto endtraverse
							}

						}

					}

				}
			}

		}
	endtraverse:
	}

	// Create output file if it doesn't exist.
	_, err = os.Stat(outputFile)
	if err != nil {
		if os.IsNotExist(err) {
			_, err = os.Create(outputFile)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	err = os.Truncate(outputFile, 0)
	if err != nil {
		log.Fatal(err)
	}

	file, err := os.OpenFile(
		outputFile,
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
		0777,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)

	for _, value := range output {
		err := writer.Write(value)
		if err != nil {
			log.Fatal(err)
		}

	}

	defer writer.Flush()

	var outputLongLat = [][]string{}

	// geocode

	c, err := maps.NewClient(maps.WithAPIKey("AIzaSyDfhN0CsQO-4Ynyk2OGtTaFGXwxxQtqZSY"))
	if err != nil {
		log.Fatalf("fatal error: %s", err)
	}


	for _, value := range output {

		var longLatPair = []string{}

		addr := value[4]
		//fmt.Println(addr)

		r := &maps.GeocodingRequest{
			Address: addr,
		}


		res, err := c.Geocode(context.Background(), r)

		if err != nil {

			fmt.Println("error "+ err.Error() + "skipping")
			continue
		}

		// fmt.Println(res)

		lngStr := strconv.FormatFloat(res[0].Geometry.Location.Lng, 'f', -1, 64)
		latStr := strconv.FormatFloat(res[0].Geometry.Location.Lat, 'f', -1, 64)

		fmt.Println(value[4] + " " + lngStr +", "+ latStr)

		longLatPair = append(longLatPair, value[4])
		longLatPair = append(longLatPair, lngStr)
		longLatPair = append(longLatPair, latStr)
		outputLongLat = append(outputLongLat , longLatPair)

	}


	// Create output file if it doesn't exist.
	_, err = os.Stat(outputLongLatFile)
	if err != nil {
		if os.IsNotExist(err) {
			_, err = os.Create(outputLongLatFile)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	err = os.Truncate(outputLongLatFile, 0)
	if err != nil {
		log.Fatal(err)
	}

	file, err = os.OpenFile(
		outputLongLatFile,
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
		0777,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	writer = csv.NewWriter(file)

	for _, value := range outputLongLat {
		err := writer.Write(value)
		if err != nil {
			log.Fatal(err)
		}

	}

	defer writer.Flush()

}
