import org.jsoup.Jsoup
import org.jsoup.nodes.Document
import org.jsoup.nodes.Element
import org.jsoup.select.Elements
import java.net.URLEncoder
import com.sap.gateway.ip.core.customdev.util.Message

def callUrl(authenticityToken, xsrfProtection, state, nonce, jsessionId) {
    def url = "https://awx6f6jot.accounts.ondemand.com/saml2/idp/sso"

    // Body-Parameter
    def relayState = "client_id=848f48cf-94fd-46a7-9faf-2f108036409d&response_type=code&redirect_uri=https%3A%2F%2Fsap-ain-azure-vhqbm59d.authentication.eu20.hana.ondemand.com%2Flogin%2Fcallback%2Fsap.custom&state=${state}&scope=openid+email&nonce=${nonce}"
    def targetUrl = "https%3A%2F%2Fawx6f6jot.accounts.ondemand.com%2Foauth2%2Fauthorize%3Fclient_id%3D848f48cf-94fd-46a7-9faf-2f108036409d%26response_type%3Dcode%26redirect_uri%3Dhttps%253A%252F%252Fsap-ain-azure-vhqbm59d.authentication.eu20.hana.ondemand.com%252Flogin%252Fcallback%252Fsap.custom%26state%3D${state}%26scope%3Dopenid%2Bemail%26nonce%3D${nonce}"

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

    // Cookie-Parameter
    def cookies = [
        "XSRF_COOKIE": xsrfProtection,
        "JSESSIONID": jsessionId
    ]

    // Header-Parameter
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
        "sec-ch-ua-platform": "\"Windows\""
    ]

    // Parameter und Header zu URL-kodiertem String konvertieren
    def bodyParamsString = bodyParams.collect { key, value -> "${key}=${value}" }.join("&")

    println(bodyParamsString)

    // URL aufrufen und Response zurückgeben
    def response = Jsoup.connect(url)
            .requestBody(bodyParamsString)
            .cookies(cookies)
            .headers(headers)
            .method(org.jsoup.Connection.Method.POST)
            .execute()
    return response
}

def Message login(Message message) {

    def authenticityTokenValue = message.getProperty('csrfToken')
    def xsrfProtectionValue = message.getProperty('xsrfProtectionField')
    def stateValue = message.getProperty('State')
    def nonceValue = message.getProperty('Nonce')
    def jsessionIdValue = message.getProperty('jsessionId')

    def messageLog = messageLogFactory.getMessageLog(message)
    messageLog.setStringProperty('authenticityTokenValue', authenticityTokenValue)
    messageLog.setStringProperty('xsrfProtectionValue', xsrfProtectionValue)
    messageLog.setStringProperty('stateValue', stateValue)
    messageLog.setStringProperty('nonceValue', nonceValue)
    messageLog.setStringProperty('jsessionIdValue', jsessionIdValue)

    def response = callUrl(authenticityTokenValue, xsrfProtectionValue, stateValue, nonceValue, jsessionIdValue)
    message.setBody(response.parse())

    return message
}
