// Sample file with intentional vulnerabilities for testing sicario

const password = "super_secret_123";
const api_key = "sk-live-abc123xyz";

function processUserInput(userInput) {
    // VULN: eval injection
    eval(userInput);

    // VULN: XSS via innerHTML
    document.getElementById("output").innerHTML = userInput;

    // VULN: document.write XSS
    document.write(userInput);
}

function generateToken() {
    // VULN: Math.random is not cryptographically secure
    return Math.random().toString(36);
}

function debugAuth(token) {
    // VULN: logging sensitive data
    console.log(token);
}
