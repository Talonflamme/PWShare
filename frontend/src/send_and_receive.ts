const sendButton = document.getElementById("send-button") as HTMLButtonElement;
const receiveButton = document.getElementById("receive-button") as HTMLButtonElement;


sendButton.addEventListener("click", () => {
    // TODO: send POST to server
    console.log("Sending POST...");

    const input = document.getElementById("main-input") as HTMLInputElement;

    fetch("http://localhost:4981", {
        method: "POST",
        body: input.value
    }).then(resp => {
        if (!resp.ok) {
            console.error("Failed POST request");
        }
    });
});

receiveButton.addEventListener("click", () => {
    console.log("Sending GET...");

    const input = document.getElementById("main-input") as HTMLInputElement;

    fetch("http://localhost:4981", { method: "GET"}).then(resp => {
        if (!resp.ok) {
            console.error("Failed GET request");
            return;
        }

        resp.text().then(text => {
            input.value = text;
        });
    });
});
