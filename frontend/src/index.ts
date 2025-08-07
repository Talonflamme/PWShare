import "./style.scss";
import './mouse-glow-effect';
import './copy-password';
import './send_and_receive';


const mainInput = document.getElementById("main-input") as HTMLInputElement;

document.getElementById("send-button")!.addEventListener("click", () => {
    const valueToSend = mainInput.value;
    // encrypt value, send it to other device
});
