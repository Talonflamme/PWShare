import './mouse-glow-effect.scss';

function mouseGlowEffectListener(e: MouseEvent) {
    const target = e.currentTarget as HTMLElement;
    const bounds = target.getBoundingClientRect();
    const x = e.clientX - bounds.left;
    const y = e.clientY - bounds.top;
    target.style.setProperty("--mouse-x", `${x}px`);
    target.style.setProperty("--mouse-y", `${y}px`);
}

document.querySelectorAll(".mouse-glow-effect").forEach(el => (el as HTMLElement).addEventListener("mousemove",  mouseGlowEffectListener));
