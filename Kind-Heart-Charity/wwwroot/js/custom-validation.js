// custom-validation.js
function validateSignUpForm() {
    debugger
    const nameInput = document.getElementById("Name").value;
    const emailInput = document.getElementById("Email").value;
    const passwordInput = document.getElementById("Password").value;
    const retypePasswordInput = document.getElementById("RetypePassword").value;

    // Check if fields are not empty
    if (!nameInput.trim()) {
        alert("Please enter your full name.");
        return false;
    }

    if (!emailInput.trim()) {
        alert("Please enter your email address.");
        return false;
    }

    if (!passwordInput.trim()) {
        alert("Please enter a password.");
        return false;
    }

    if (!retypePasswordInput.trim()) {
        alert("Please retype the password.");
        return false;
    }

    // Check if the password meets the required criteria
    if (passwordInput.length < 7) {
        alert("Password must be at least 7 characters long.");
        return false;
    }

    const hasNumber = /\d/.test(passwordInput);
    const hasCharacter = /[!@#$%^&*(),.?":{}|<>]/.test(passwordInput);
    const hasAlphabet = /[a-zA-Z]/.test(passwordInput);

    if (!(hasNumber && hasCharacter && hasAlphabet)) {
        alert("Password must contain at least one numeric, one character, and one alphabet.");
        return false;
    }

    // Check if passwords match
    if (passwordInput !== retypePasswordInput) {
        alert("Passwords do not match.");
        return false;
    }

    // Check if the terms are agreed
    const agreeTermsInput = document.getElementById("agreeTerms").checked;
    if (!agreeTermsInput) {
        alert("Please agree to the terms.");
        return false;
    }

    return true;
}

// Hook up the validation function to the form submit event
document.querySelector("form").addEventListener("submit", function (event) {
    debugger
    if (!validateSignUpForm()) {
        event.preventDefault(); // Prevent form submission if validation fails
    }
});
