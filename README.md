# OWASP JUICE SHOP - WEB SECURITY TESTING - TERM PROJECT REPORT

# About
Our project focuses on web application security testing, specifically utilizing static and dynamic analysis tools available for this purpose. As our target application, we selected OWASP Juice Shop, an intentionally vulnerable open-source application designed for testing web security tools. We aim to demonstrate the effectiveness of various security testing tools in a real-world context without legal constraints.

# Testing
- Static Analysis Security Testing (SAST)
- Dynamic Analysis Security Testing (DAST)

# Tools
- NodeJsScan
   - Static Analysis Security Testing
  
- OWASP ZAP
   - Static Analysis Security Testing (SAST)
   - Dynamic Analysis Security Testing (DAST)

These tools were chosen based on their popularity and effectiveness in testing web application security.

# Practical Investigation
## NodeJsScan
NodeJsScan is a static security code scanner for Node.js applications. It's designed to automatically review `Node.js` application code for security flaws and vulnerabilities. It analyzes the source code to find security issues that could potentially lead to security breaches, such as SQL injection, Cross-Site Scripting (XSS), command injection, and more. It was developed to fill the gap in web security analysis landscape, by focusing on server-side aspect of JavaScript, which was previously overlooked by existing SAST tools. NodeJsScan can be used as a standalone application or integrated with Continuous Integration (CI) tools to automate security testing. It supports various JavaScript and TypeScript frameworks used in Node.js development and provides detailed reports on the findings to aid in the remediation process. (Abraham, 2024).

## Static Analysis Securtiy Testing (SAST)
Firstly, we performed the static testing to analyze the software security issues. We are using NodeJSScan because it is used test the Node.js applications and Juice Shop is based on Node.js environment. For this, we have to clone the OWASP Juice Shop application in the working directory. After that, we need NodeJSScan software to conduct the static testing. Therefore, we used the `Docker` which is a software platform to build, test, and deploy applications. 

Similarly, we pull the nodejsscan latest image from the repository and started to use this application. Below, it is a screenshot where run the Docker software and run the application on port 9090 to access it on browser:
- `docker run -it -p 9090:9090 opensecurity/nodejsscan:latest`

![Docker](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/nodejsscan/1.png)

This is a screenshot of Docker tool where we created the instance for nodejsscan image, known as container running on the 9090 port, highlighted in red:

![Docker](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/nodejsscan/2.png)

After creating container, we were able to access the NodeJSScan image in the  browser on port 9090 with localhost. Here, we can use the zip file or provide the url of application but we used the zip file to create the scan:

![Docker](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/nodejsscan/3.png)

Further, you can see after uploading the zip file of Juice Shop, we performed the static analysis and also save the results:

![Docker](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/nodejsscan/4.png)

After completing the analysis, we can see the complete scan in the form of graph and charts where we encountered total 15 issues:

![Docker](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/nodejsscan/5.png)

In this scan, the major vulnerability that we received from NodeJsScan is regarding the use of the **MD5 hashing algorithm** in the code. MD5 refers to **Message Digest Algorithm 5** is a widely used cryptographic hash function that produces a **128-bit (16-byte) hash** value. However, MD5 is considered as weak and insecure because collisions. It means two different inputs producing the same hash. It can be found relatively easily due to vulnerabilities in the algorithm. As a result, it can open up the possibility of attacks such as collision attacks and pre-image attacks, which undermine the security of the system. 

![Docker](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/nodejsscan/6.png)

To get clear understanding of this issue, we can elaborate it with this example:
- We import the crypto module, which provides cryptographic feature.
- Then define a string `dataForHash` that we want to hash.
- For MD5 hashing, we create a hash object using `crypto.createHash('md5')` just like in the below picture. Then update it with the data to be hashed using **.update(dataToHash)**, and finally convert it to get the hexadecimal hash value using `.digest('hex')`.
 
![Docker](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/nodejsscan/7.png)

In the screenshot, we can check the issue severity which is warning and we can also locate the code in the file where the issue actually persists:

![Docker](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/nodejsscan/8.png)

# Solution:
This tool also provides the hint for possible solution to recover the application from this error. The solution to this problem is to replace MD5 with a more secure hashing algorithm, which can be `SHA-256` (Secure Hash Algorithm 256-bit), `SHA-3` (Secure Hash Algorithm 3), or `bcrypt`, which are designed to be more resistant to these kinds of cryptographic attacks. These algorithms provide stronger security guarantees and are recommended for use in modern applications where data security is a major concern for client.
Lets take a example of SHA-256 hashing algorithm:
- Similar to `MD5`, for SHA-256 hashing, we generate a hash object with the  help of using this function, `crypto.createHash('sha256')`.
- Then update it with the data to be hashed using `.update(dataForHash)`.
- Finally, convert it to get the hexadecimal hash value using `.digest('hex')`.


## OWASP ZAP 
OWASP ZAP (Zed Attack Proxy) is an open-source web application security scanner maintained by the Open Web Application Security Project (OWASP). It is designed to help users identify security vulnerabilities in web applications during development and testing phases. ZAP provides various features such as automated scanning, manual testing tools, and a powerful API for integration with other tools and workflows. The Zed Attack Proxy (ZAP) is one of the world’s most popular free security tools and it can help you automatically find security vulnerabilities in your web applications while you are developing and testing your applications.

## Automated Testing
In the initial step of using ZAP (Zed Attack Proxy) for security assessments on websites, enter the target site's URL and select `Active Attack`. This starts ZAP's attack process, which involves methodically scanning the website for flaws, warnings, and vulnerabilities. ZAP offers comprehensive comments and recommendations for improving the website's security as the attack goes on. ZAP simulates actual attack scenarios by sending payloads to the website while it is in active attack mode.

![Automated Testing](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/zap/1.png)

![Automated Testing](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/zap/2.png)

After ZAP has finished its evaluation, customers can choose to get a report in the format of their choice. The results of the security evaluation are summarized in this report, which provide insightful information about the website's weaknesses and possible areas for development. We have generated a report in two formats including HTML and HTML with JSON, which are attached in the final submission. 

![Manual Testing](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/zap/3.png)

## Manual Testing
### SQL Injection / Database Attack
SQL injection vulnerability is one that ZAP frequently finds. This happens when an attacker tinkers with the input fields of a web application in order to run malicious SQL queries on the database underneath. ZAP can identify vulnerabilities in the database processing of a website by detecting input such as `{"email":"'","password":"wdfd3646325"}`.

![Manual Testing](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/zap/4.png)

Upon analyzing the results, ZAP may reveal instances where the website fails to properly sanitize user input, leading to SQL errors or unintended behavior. For instance, if the payload `{"email":"' OR 1=1 --","password":"wdfd3646325"}` is submitted, the website may display sensitive information or behave unexpectedly, potentially exposing critical data.

![Manual Testing](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/zap/5.png)

This website is vulnerable to its database when this payload is entered `{"email":"' OR 1=1 --","password":"wdfd3646325"}`. By taking advantage of SQL injection flaws, someone can obtain administrator credentials or even sensitive data without authorization. Malicious actors pose serious risks to the integrity of the website and the security of its users since they may carry out a wide range of destructive activities, including altering content, stealing data, or interfering with services, when they have access to administrator accounts.

![Manual Testing](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/zap/6.png)

It should return as `{invalid email or password}` but it shows some error and returned “Admin” email as shown in the below screenshot

![Manual Testing](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/zap/7.png)

By using that admin credential, any user can get admin’s access and do all kind of harmful actions on the website which has access to admins only.

![Manual Testing](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/zap/8.png)

### SQL Payload
ZAP further offers information on particular SQL injection payloads that result in vulnerabilities. In order to demonstrate the possible consequences of exploiting SQL injection problems, examples include inserting queries like:
-	`') UNION SELECT * FROM Users WHERE username='admin'--`
-	`; DROP TABLE Users;--`

### Fuzzer Attack
ZAP may also find vulnerabilities using fuzzing attacks, which include testing input fields with different values in a methodical way to find flaws. A fuzzing attack, for example, can highlight possible privacy breaches by revealing that the website unintentionally exposes other users' data, including the goods in their shopping carts.
Using OWASP ZAP, a variety of unexpected and malformed input payloads were methodically fed into the designated input fields and parameters during the fuzzing attack on the OWASP Juice Shop website. The purpose of these payloads was to evaluate the application's resistance to typical security flaws including SQL injection, path traversal, and Cross-Site Scripting (XSS). OWASP ZAP carefully examined the application's answers to the injected payloads while the fuzzing process went on, keeping an eye out for any strange behaviour or unexpected results. The application's input validation and processing procedures may have been vulnerable to fuzzing attacks, which made it possible to identify security flaws that an attacker may exploit.

### Cross-Site Scripting (XSS) Payloads:
ZAP also helps find Cross-Site Scripting (XSS) vulnerabilities by evaluating payloads intended to run malicious scripts in the context of the website. These flaws provide hackers with the ability to run arbitrary code in users' browsers, which might result in more exploitation or data theft. Through the examination of payloads, ZAP is able to identify instances on the website where appropriate input validation and output encoding are lacking, thus rendering it vulnerable to XSS assaults.
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert('XSS')>`
- `<svg/onload=alert('XSS')>`
- `'><script>alert('XSS')</script>`

When we tried to run one of the above scripts, the website didn’t show any error as it has no security implemented on it.

![Manual Testing](https://github.com/KinzaGhaffar/juice-shop-security-tests/blob/main/images/zap/9.png)

## Discussion & Conclusion
Our project underscores the importance of using a combination of static and dynamic analysis tools for comprehensive web application security testing. While static analysis tools offer scalability and early bug detection, dynamic analysis tools provide insights into runtime vulnerabilities. Integrating both approaches is essential for effective vulnerability management and ensuring the security of web applications against evolving threats.
