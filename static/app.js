document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".delete-trip-button").forEach((button) => {
    button.closest("form").addEventListener("submit", (event) => {
      if (!window.confirm(button.dataset.confirm)) {
        event.preventDefault();
      }
    });
  });
});