<%--
  ~ Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
  ~
  ~ WSO2 LLC. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>

<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.apache.commons.lang.StringUtils" %>
<%@ page import="org.owasp.encoder.Encode" %>

<%
    // Retrieve parameters from the request.
    String sessionDataKey = request.getParameter("sessionDataKey");
    String authenticators = request.getParameter("authenticators");
    String requestUri = request.getParameter("requestUri");

    // Validate required parameters.
    if (StringUtils.isBlank(sessionDataKey) || StringUtils.isBlank(requestUri)) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing required parameters");
        return;
    }
%>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wallet Login - WSO2 Identity Server</title>
    <link rel="stylesheet" href="../css/wallet-login.css">
    <!-- QR Code generation library -->
    <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }

        .wallet-login-container {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 40px;
            max-width: 500px;
            text-align: center;
        }

        .wallet-login-container h2 {
            color: #333;
            margin-bottom: 10px;
        }

        .wallet-login-container p {
            color: #666;
            margin-bottom: 30px;
        }

        .qr-code-container {
            display: flex;
            justify-content: center;
            margin: 30px 0;
            padding: 20px;
            background-color: #fafafa;
            border-radius: 8px;
        }

        #qrcode {
            /* QR code will be rendered here */
        }

        .instructions {
            color: #666;
            font-size: 14px;
            line-height: 1.6;
            text-align: left;
            margin-top: 20px;
        }

        .instructions ol {
            padding-left: 20px;
        }

        .instructions li {
            margin-bottom: 10px;
        }

        .deep-link-button {
            display: inline-block;
            margin-top: 20px;
            padding: 12px 24px;
            background-color: #ff7300;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-weight: bold;
            cursor: pointer;
            border: none;
            font-size: 16px;
        }

        .deep-link-button:hover {
            background-color: #e66a00;
        }

        .loading-message {
            color: #666;
            font-style: italic;
            margin-top: 20px;
        }

        .error-message {
            color: #d9534f;
            background-color: #f2dede;
            border: 1px solid #ebccd1;
            border-radius: 4px;
            padding: 12px;
            margin-top: 20px;
        }

        .wso2-logo {
            width: 150px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="wallet-login-container">
        <!-- WSO2 Logo (optional - replace with actual logo path) -->
        <!-- <img src="../images/wso2-logo.png" alt="WSO2" class="wso2-logo"> -->

        <h2>Sign In with Your Digital Wallet</h2>
        <p>Scan the QR code with your OpenID4VP-compliant digital wallet app</p>

        <!-- QR Code Container -->
        <div class="qr-code-container">
            <div id="qrcode"></div>
        </div>

        <!-- Deep Link Button (for mobile devices) -->
        <a href="<%= Encode.forHtmlAttribute(requestUri) %>" class="deep-link-button" id="deepLinkButton">
            Open in Wallet App
        </a>

        <!-- Instructions -->
        <div class="instructions">
            <strong>How to sign in:</strong>
            <ol>
                <li>Open your digital wallet app on your mobile device</li>
                <li>Scan the QR code displayed above</li>
                <li>Review and approve the credential request</li>
                <li>You will be automatically signed in</li>
            </ol>
        </div>

        <!-- Loading Message (optional) -->
        <div id="loadingMessage" class="loading-message" style="display: none;">
            Waiting for wallet response...
        </div>

        <!-- Error Message (optional) -->
        <div id="errorMessage" class="error-message" style="display: none;">
            An error occurred. Please try again.
        </div>
    </div>

    <script>
        // Generate QR code from the OpenID4VP request URI.
        var requestUri = "<%= Encode.forJavaScript(requestUri) %>";

        if (requestUri) {
            try {
                // Create QR code.
                var qrcode = new QRCode(document.getElementById("qrcode"), {
                    text: requestUri,
                    width: 256,
                    height: 256,
                    colorDark: "#000000",
                    colorLight: "#ffffff",
                    correctLevel: QRCode.CorrectLevel.H
                });

                console.log("QR code generated successfully");
            } catch (error) {
                console.error("Error generating QR code:", error);
                document.getElementById("errorMessage").style.display = "block";
                document.getElementById("errorMessage").textContent = "Failed to generate QR code: " + error.message;
            }
        } else {
            document.getElementById("errorMessage").style.display = "block";
            document.getElementById("errorMessage").textContent = "Invalid request URI";
        }

        // Optional: Polling mechanism to check if authentication is complete.
        // This would require a backend endpoint to check authentication status.
        /*
        var pollInterval = setInterval(function() {
            fetch('/checkAuthStatus?sessionDataKey=<%= Encode.forJavaScript(sessionDataKey) %>')
                .then(response => response.json())
                .then(data => {
                    if (data.completed) {
                        clearInterval(pollInterval);
                        document.getElementById("loadingMessage").style.display = "block";
                        document.getElementById("loadingMessage").textContent = "Authentication successful! Redirecting...";
                        // Redirect or refresh as needed
                    }
                })
                .catch(error => console.error("Error checking auth status:", error));
        }, 2000);
        */

        // Show loading message when deep link is clicked.
        document.getElementById("deepLinkButton").addEventListener("click", function() {
            document.getElementById("loadingMessage").style.display = "block";
        });
    </script>
</body>
</html>

