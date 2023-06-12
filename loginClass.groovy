@Grab('org.jsoup:jsoup:1.14.1')
import org.jsoup.Jsoup
import org.jsoup.nodes.Document
import org.jsoup.nodes.Element
import org.jsoup.select.Elements
import org.jsoup.HttpStatusException
import org.jsoup.Connection
import org.jsoup.helper.HttpConnection

class Login {
    private String authenticationHost = "sap-ain-azure-vhqbm59d.authentication.eu20.hana.ondemand.com"
    private String loginURL = "https://sap-ain-azure-vhqbm59d.authentication.eu20.hana.ondemand.com/login"
    private String authorizeURL = "https://awx6f6jot.accounts.ondemand.com"
    private String clientID = "848f48cf-94fd-46a7-9faf-2f108036409d"
    private String redirectURI = "https://sap-ain-azure-vhqbm59d.authentication.eu20.hana.ondemand.com/login/callback/sap.custom"
    private String xsuaaID = "XSUAA_f6acc815-0230-4904-acf0-620343d23ca7"
    private String spID = "64788d7144222c41b27ad3c7"
    private username = "Lorenz.weiss@sce.valantic.com"
    private password = "M4!@X9dThAqz"

    private String nonce
    private String state
    private Map cookiesFromLogin

    private String oAuthAuthorize_csrfToken
    private String oAuthAuthorize_xsrfProtection
    private String oAuthAuthorize_jsessionId
    private Map oAuthAuthorize_cookies

    private HttpConnection.Response response_from_post_login

    def callLoginPage(){

        def headers = [
            "authority": this.authenticationHost,
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
            "Host": this.authenticationHost
        ]

        def loginResponse = Jsoup.connect(this.loginURL)
                              .headers(headers)
                              .execute()

        def loginHtml = loginResponse.parse().html()

        Document doc = Jsoup.parse(loginHtml)
        def redirectMeta = doc.select('meta[name=redirect]').first()
        def redirectContent = redirectMeta.attr('content')

        def state = redirectContent.split('&').find { it.startsWith('state=') }
        def nonce = redirectContent.split('&').find { it.startsWith('nonce=') }

        if (state) {
            this.state = state.split('=')[1]
        }

        if (nonce) {
            this.nonce = nonce.split('=')[1]
        }

        this.cookiesFromLogin = loginResponse.cookies();

    }

    def callOAuthAuthorize() {
        def redirectURI = URLEncoder.encode(this.redirectURI, "UTF-8")
        def url = "${this.authorizeURL}/oauth2/authorize?client_id=${this.clientID}&response_type=code&redirect_uri=${redirectURI}&state=${this.state}&scope=openid+email&nonce=${this.nonce}"

        def headers = [
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-site",
            "Referer": "${this.loginURL}/callback/sap.custom".toString(),
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
        this.oAuthAuthorize_csrfToken = doc.select("meta[name=csrf-token]").attr("content")
        this.oAuthAuthorize_xsrfProtection = doc.select("#hidden-xsrfProtection-field").attr("value")
        this.oAuthAuthorize_jsessionId = response.cookie("JSESSIONID")

        this.oAuthAuthorize_cookies = response.cookies();
    }

    def callPostLogin() {

        def url = "${this.authorizeURL}/saml2/idp/sso".toString()

        def redirectUriRelayState = "${this.loginURL}/callback/sap.custom".toString()
        redirectUriRelayState = URLEncoder.encode(redirectUriRelayState, "UTF-8")

        def relayState = "client_id=${this.clientID}&response_type=code&redirect_uri=${redirectUriRelayState}&state=${this.state}&scope=openid+email&nonce=${this.nonce}".toString()
        // relayState = URLEncoder.encode(relayState, "UTF-8")

        def redirect_uri = URLEncoder.encode("${this.loginURL}/login/callback/sap.custom", "UTF-8")
        def targetUrl = "${this.authorizeURL}/oauth2/authorize?client_id=${this.clientID}&response_type=code&redirect_uri=${redirect_uri}&state=${this.state}&scope=openid+email&nonce=${this.nonce}".toString()
        targetUrl = URLEncoder.encode(targetUrl, "UTF-8")

        def bodyParams = [
            "authenticity_token": this.oAuthAuthorize_csrfToken,
            "xsrfProtection": this.oAuthAuthorize_xsrfProtection,
            "method": "GET",
            "idpSSOEndpoint": url,
            "sp": this.xsuaaID,
            "RelayState": relayState,
            "targetUrl": targetUrl,
            "sourceUrl": "",
            "org": "",
            "spId": this.spID,
            "spName": this.xsuaaID,
            "mobileSSOToken": "",
            "tfaToken": "",
            "css": "",
            "passwordlessAuthnSelected": "",
            "j_username": this.username,
            "j_password": this.password
        ]

        def headers = [
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "${this.authorizeURL}".toString(),
            "Pragma": "no-cache",
            "Referer": "${this.authorizeURL}/".toString(),
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
            this.response_from_post_login = Jsoup.connect(url)
                    .requestBody(requestBody)
                    .followRedirects(false)
                    .cookies(oAuthAuthorize_cookies)
                    .headers(headers)
                    .method(org.jsoup.Connection.Method.POST)
                    .execute()

        } catch (Exception e) {
            e.printStackTrace()

        }
    }

    def loginCallback() {

        def url = this.response_from_post_login.header("Location")

        Map<String, String> cookies_for_redirect = new HashMap<String, String>()
        cookies_for_redirect.put("JSESSIONID", this.cookiesFromLogin.get("JSESSIONID"))
        cookies_for_redirect.put("__VCAP_ID__", this.cookiesFromLogin.get("__VCAP_ID__"))
        cookies_for_redirect.put("X-Uaa-Csrf", this.cookiesFromLogin.get("X-Uaa-Csrf"))

        def headers = [
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": this.authorizeURL,
            "Pragma": "no-cache",
            "Referer": this.authorizeURL,
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

        try {
            def response = Jsoup.connect(url)
                    .cookies(cookies_for_redirect)
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
// System.clearProperty("https.proxyPort")
// System.clearProperty("https.proxyHost")

def login() {
    def login = new Login()

    login.callLoginPage()
    login.callOAuthAuthorize()
    login.callPostLogin()

    def response_login_callback = login.loginCallback()

    println(response_login_callback.parse().html())
}
