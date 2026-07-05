from flask import Flask, render_template, request
import requests
import ssl
import socket
from urllib.parse import urlparse

app = Flask(__name__)

SECURITY_HEADERS = {
    "Content-Security-Policy": "Prevents XSS attacks",
    "Strict-Transport-Security": "Forces HTTPS usage",
    "X-Frame-Options": "Prevents clickjacking",
    "X-Content-Type-Options": "Prevents MIME attacks",
    "Referrer-Policy": "Controls referrer information"
}


def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain,443)) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as secure_sock:

                cert = secure_sock.getpeercert()

                return {
                    "status":"Valid",
                    "issuer":cert["issuer"][0][0][1],
                    "expires":cert["notAfter"]
                }

    except:
        return {
            "status":"Not Found"
        }


@app.route("/", methods=["GET","POST"])
def home():

    results=None
    score=0

    if request.method=="POST":

        url=request.form["url"]

        if not url.startswith("http"):
            url="https://" + url

        try:

            response=requests.get(
                url,
                timeout=10
            )

            headers_result={}

            for header,description in SECURITY_HEADERS.items():

                if header in response.headers:

                    headers_result[header]={
                        "status":"Present",
                        "description":description
                    }

                    score+=15

                else:

                    headers_result[header]={
                        "status":"Missing",
                        "description":description
                    }

            cookie_data=response.headers.get(
                "Set-Cookie",
                ""
            )

            cookies={

                "Secure Flag":
                "Present"
                if "Secure" in cookie_data
                else "Missing",

                "HttpOnly Flag":
                "Present"
                if "HttpOnly" in cookie_data
                else "Missing",

                "SameSite":
                "Present"
                if "SameSite" in cookie_data
                else "Missing"
            }

            for item in cookies.values():

                if item=="Present":
                    score+=8

            parsed=urlparse(url)

            ssl_info=get_ssl_info(
                parsed.netloc
            )

            if ssl_info["status"]=="Valid":
                score+=20

            if score>100:
                score=100

            results={

                "url":url,
                "headers":headers_result,
                "cookies":cookies,
                "ssl":ssl_info
            }

        except Exception as e:

            results={
                "error":str(e)
            }

    return render_template(
        "index.html",
        results=results,
        score=score
    )


if __name__=="__main__":
    app.run(debug=True)