@Grab('org.jsoup:jsoup:1.14.1')
import org.jsoup.Jsoup
import org.jsoup.nodes.Document
import org.jsoup.nodes.Element
import org.jsoup.select.Elements
import org.jsoup.HttpStatusException
import org.jsoup.Connection
import org.jsoup.helper.HttpConnection

class Login {
    static callLoginPage(){
        def loginUrl = "https://sap-ain-azure-vhqbm59d.authentication.eu20.hana.ondemand.com/login"

        def headers = [
            "authority": "sap-ain-azure-vhqbm59d.authentication.eu20.hana.ondemand.com",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept-language": "en",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "sec-ch-ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "Host": "awx6f6jot.accounts.ondemand.com",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Host": "sap-ain-azure-vhqbm59d.authentication.eu20.hana.ondemand.com"
        ]

        def loginResponse = Jsoup.connect(loginUrl)
                              .headers(headers)
                              .execute()

        def loginHtml = loginResponse.parse().html()

        Document doc = Jsoup.parse(loginHtml)
        def redirectMeta = doc.select('meta[name=redirect]').first()
        def redirectContent = redirectMeta.attr('content')

        def state = redirectContent.split('&').find { it.startsWith('state=') }
        def nonce = redirectContent.split('&').find { it.startsWith('nonce=') }

        if (state) {
            state = state.split('=')[1]
        }

        if (nonce) {
            nonce = nonce.split('=')[1]
        }

        def cookies = loginResponse.cookies();

        return [state, nonce, cookies]
    }

    static callOAuthAuthorize(state, nonce, cookies) {
        def url = "https://awx6f6jot.accounts.ondemand.com/oauth2/authorize?client_id=848f48cf-94fd-46a7-9faf-2f108036409d&response_type=code&redirect_uri=https%3A%2F%2Fsap-ain-azure-vhqbm59d.authentication.eu20.hana.ondemand.com%2Flogin%2Fcallback%2Fsap.custom&state=${state}&scope=openid+email&nonce=${nonce}"

        def headers = [
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-site",
            "Referer": "https://sap-ain-azure-vhqbm59d.authentication.eu20.hana.ondemand.com/",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "sec-ch-ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "Host": "awx6f6jot.accounts.ondemand.com",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive"
        ]

        def response = Jsoup.connect(url)
                              .headers(headers)
                              .execute()

        def html = response.parse().html()

        Document doc = Jsoup.parse(html)
        def csrfToken = doc.select("meta[name=csrf-token]").attr("content")
        def xsrfProtectionField = doc.select("#hidden-xsrfProtection-field").attr("value")
        def jsessionId = response.cookie("JSESSIONID")

        def cookies_response = response.cookies();

        return [csrfToken, xsrfProtectionField, jsessionId, cookies_response]
    }

    static postLogin(authenticityToken, xsrfProtection, state, nonce, jsessionId, cookieauth) {

        println("state: " + state)
        println("nonce: " + nonce)
        println("xsrfProtection: " + xsrfProtection)
        println("authenticityToken: " + authenticityToken)
        println("jsessionId: " + jsessionId)

        def url = "https://awx6f6jot.accounts.ondemand.com/saml2/idp/sso"

        def relayState = "client_id=848f48cf-94fd-46a7-9faf-2f108036409d&response_type=code&redirect_uri=https%3A%2F%2Fsap-ain-azure-vhqbm59d.authentication.eu20.hana.ondemand.com%2Flogin%2Fcallback%2Fsap.custom&state=${state}&scope=openid+email&nonce=${nonce}".toString()
        def targetUrl = "https%3A%2F%2Fawx6f6jot.accounts.ondemand.com%2Foauth2%2Fauthorize%3Fclient_id%3D848f48cf-94fd-46a7-9faf-2f108036409d%26response_type%3Dcode%26redirect_uri%3Dhttps%253A%252F%252Fsap-ain-azure-vhqbm59d.authentication.eu20.hana.ondemand.com%252Flogin%252Fcallback%252Fsap.custom%26state%3D${state}%26scope%3Dopenid%2Bemail%26nonce%3D${nonce}".toString()

        println("relayState: ${relayState}")
        println("targetUrl: ${targetUrl}")

        def bodyParams = [
            "authenticity_token": authenticityToken,
            "xsrfProtection": xsrfProtection,
            "method": "GET",
            "idpSSOEndpoint": url,
            "sp": "XSUAA_f6acc815-0230-4904-acf0-620343d23ca7",
            "RelayState": relayState,
            "targetUrl": targetUrl,
            "sourceUrl": "",
            "org": "",
            "spId": "64788d7144222c41b27ad3c7",
            "spName": "XSUAA_f6acc815-0230-4904-acf0-620343d23ca7",
            "mobileSSOToken": "",
            "tfaToken": "",
            "css": "",
            "passwordlessAuthnSelected": "",
            "j_username": "Lorenz.weiss@sce.valantic.com",
            "j_password": "M4!@X9dThAqz"
        ]

        def headers = [
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://awx6f6jot.accounts.ondemand.com",
            "Pragma": "no-cache",
            "Referer": "https://awx6f6jot.accounts.ondemand.com/",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "sec-ch-ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "Accept-Encoding": "gzip, deflate, br"
        ]

        def requestBody = bodyParams.collect { k, v -> "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v, "UTF-8")}" }.join("&")

        try {
            def response = Jsoup.connect(url)
                    .requestBody(requestBody)
                    .followRedirects(false)
                    .cookies(cookieauth)
                    .headers(headers)
                    .method(org.jsoup.Connection.Method.POST)
                    .execute()

            return response

        } catch (Exception e) {
            e.printStackTrace()

        }
    }

    static loginCallback(response_from_post_login, cookieslogin) {

        def url = response_from_post_login.header("Location")

        Map<String, String> newMap = new HashMap<String, String>()
        newMap.put("JSESSIONID", cookieslogin.get("JSESSIONID"))
        newMap.put("__VCAP_ID__", cookieslogin.get("__VCAP_ID__"))
        newMap.put("X-Uaa-Csrf", cookieslogin.get("X-Uaa-Csrf"))

        def headers = [
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://awx6f6jot.accounts.ondemand.com",
            "Pragma": "no-cache",
            "Referer": "https://awx6f6jot.accounts.ondemand.com/saml2/idp/sso",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "sec-ch-ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "Accept-Encoding": "gzip, deflate, br",
            "Postman-Token": "40c56f9a-1e29-4caa-939f-d8cbcbe7a084"
        ]

        try {
            def response = Jsoup.connect(url)
                    .cookies(newMap)
                    .headers(headers)
                    .execute()

            return response

        } catch (Exception e) {
            println(e.getMessage())
            e.printStackTrace()

        }
    }
}

System.setProperty("https.proxyHost", "localhost")
System.setProperty("https.proxyPort", "8866")

def state_noce_cookie = Login.callLoginPage()
def state = state_noce_cookie[0]
def nonce = state_noce_cookie[1]
def cookieslogin = state_noce_cookie[2]

def xsrfProtection_csrfToken_jsessionId = Login.callOAuthAuthorize(state, nonce, cookieslogin)
def csrfToken = xsrfProtection_csrfToken_jsessionId[0]
def xsrfProtection = xsrfProtection_csrfToken_jsessionId[1]
def jsessionId = xsrfProtection_csrfToken_jsessionId[2]
def cookieauth = xsrfProtection_csrfToken_jsessionId[3]

def response = Login.postLogin(csrfToken, xsrfProtection, state, nonce, jsessionId, cookieauth)
def response_login_callback = Login.loginCallback(response, cookieslogin)

println(response_login_callback.parse().html())
