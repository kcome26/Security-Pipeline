// Hardcoded credentials - security issue for testing
const password = "hardcoded_password";

function main() {
    console.log("Hello from JavaScript");
    // SQL injection vulnerability example
    const userId = process.argv[2];
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    console.log(query);
}

main();
