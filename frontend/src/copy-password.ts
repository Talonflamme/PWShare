import CopyImageSrc from './images/copy.svg';
import CheckMarkImageSrc from './images/checkmark.svg';


function clearIcons() {
    document.querySelectorAll(".copy-icon>img").forEach(img => {
        (img as HTMLImageElement).src = CopyImageSrc;
    });
}

document.querySelectorAll(".copy-icon").forEach(x => {
    x.querySelector("img")!.src = CopyImageSrc;
    x.addEventListener("click", e => {
        const span = e.currentTarget as HTMLSpanElement;
        const img = span.querySelector("img")!;
        img.src = CheckMarkImageSrc;

        // copy text of input to clipboard
        const inputElement = span.parentElement!.querySelector("input")!;
        navigator.clipboard.writeText(inputElement.value);
    });
});

window.addEventListener("blur", () => {
    clearIcons();
});
