document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".analysis-form").forEach((form) => {
    form.addEventListener("submit", () => {
      const button = form.querySelector(".analysis-submit");
      const progress = form.querySelector(".analysis-progress");
      if (button) {
        button.disabled = true;
        button.textContent = "正在分析…";
      }
      if (progress) progress.hidden = false;
    });
  });
});
