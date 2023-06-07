@Grab('org.jsoup:jsoup:1.14.1')
import org.jsoup.Jsoup
import org.jsoup.nodes.Document
import org.jsoup.nodes.Element
import org.jsoup.select.Elements
import org.jsoup.HttpStatusException

class Login {
    static callLoginPage(){
        def loginUrl = "https://sap-ain-azure-vhqbm59d.authentication.eu20.hana.ondemand.com/login"

        def headers = [
            "authority": "sap-ain-azure-vhqbm59d.authentication.eu20.hana.ondemand.com",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en",
            "Cache-Control": "no-cache",
            "pragma": "no-cache",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "sec-fetch-site": "none",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
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

        Map<String, String> cookies = loginResponse.cookies();

        return [state, nonce, cookies]
    }

    static callOAuthAuthorize(state, nonce, cookies) {
        def url = "https://awx6f6jot.accounts.ondemand.com/oauth2/authorize?client_id=848f48cf-94fd-46a7-9faf-2f108036409d&response_type=code&redirect_uri=https%3A%2F%2Fsap-ain-azure-vhqbm59d.authentication.eu20.hana.ondemand.com%2Flogin%2Fcallback%2Fsap.custom&state=${state}&scope=openid+email&nonce=${nonce}"

        println("cookies: " + cookies)

        def response = Jsoup.connect(url)
                              .cookies(cookies)
                              .execute()

        def html = response.parse().html()

        Document doc = Jsoup.parse(html)
        def csrfToken = doc.select("meta[name=csrf-token]").attr("content")
        def xsrfProtectionField = doc.select("#hidden-xsrfProtection-field").attr("value")
        def jsessionId = response.cookie("JSESSIONID")

        return [csrfToken, xsrfProtectionField, jsessionId]
    }

    static postLogin(authenticityToken, xsrfProtection, state, nonce, jsessionId) {

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
            "j_password": "M4!@X9dThAqz",
        ]

        def test = "\"${xsrfProtection}\""

        def cookies = [
            "JSESSIONID": jsessionId,
            "XSRF_COOKIE": test.toString()
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

        println("treeeeeeestststst");

        def requestBody = bodyParams.collect { k, v -> "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v, "UTF-8")}" }.join("&")
        println(requestBody);

        try {
            def response = Jsoup.connect(url)
                    .requestBody(requestBody)
                    .cookies(cookies)
                    .headers(headers)
                    .method(org.jsoup.Connection.Method.POST)
                    .execute()

            return response

        } catch (Exception e) {
            println(e.getMessage())
            e.printStackTrace()

            println("Fehler beim Ausführen des Requests:")
            println("URL: " + url)
            println("Request-Methode: " + org.jsoup.Connection.Method.POST)
            println("Request-Body: " + bodyParams)
            println("Cookies: " + cookies)
            println("Headers: " + headers)
        }
    }
}

// System.setProperty("http.proxyHost", "localhost")
// System.setProperty("http.proxyPort", "8888")

System.setProperty("https.proxyHost", "localhost")
System.setProperty("https.proxyPort", "8866")

def state_noce_cookie = Login.callLoginPage()
def state = state_noce_cookie[0]
def nonce = state_noce_cookie[1]
def cookies = state_noce_cookie[2]

def xsrfProtection_csrfToken_jsessionId = Login.callOAuthAuthorize(state, nonce, cookies)
def csrfToken = xsrfProtection_csrfToken_jsessionId[0]
def xsrfProtection = xsrfProtection_csrfToken_jsessionId[1]
def jsessionId = xsrfProtection_csrfToken_jsessionId[2]

def response = Login.postLogin(csrfToken, xsrfProtection, state, nonce, jsessionId)
println(response.parse().html())
