/* BarangayConnect - front-end behaviours */
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", function () {

    /* ---------- Sidebar (mobile) toggle ---------- */
    var sidebar = document.getElementById("adminSidebar");
    var toggleBtn = document.getElementById("sidebarToggle");
    var backdrop = null;

    function closeSidebar() {
      if (!sidebar) return;
      sidebar.classList.remove("show");
      if (backdrop) { backdrop.remove(); backdrop = null; }
    }

    if (sidebar && toggleBtn) {
      toggleBtn.addEventListener("click", function () {
        var isOpen = sidebar.classList.toggle("show");
        if (isOpen) {
          backdrop = document.createElement("div");
          backdrop.className = "sidebar-backdrop";
          backdrop.addEventListener("click", closeSidebar);
          document.body.appendChild(backdrop);
        } else {
          closeSidebar();
        }
      });
      document.addEventListener("keydown", function (e) {
        if (e.key === "Escape") closeSidebar();
      });
      // Close menu when a nav link is chosen on mobile
      sidebar.querySelectorAll("a").forEach(function (a) {
        a.addEventListener("click", function () {
          if (window.innerWidth < 992) closeSidebar();
        });
      });
    }

    /* ---------- Toast notifications from Flask flash messages ---------- */
    var toastArea = document.getElementById("toastArea");
    var CATEGORY_STYLE = {
      success: { bg: "text-bg-success",   icon: "bi-check-circle-fill" },
      danger:  { bg: "text-bg-danger",    icon: "bi-exclamation-triangle-fill" },
      warning: { bg: "text-bg-warning",   icon: "bi-exclamation-circle-fill" },
      info:    { bg: "text-bg-info",      icon: "bi-info-circle-fill" },
      dark:    { bg: "text-bg-dark",      icon: "bi-bell-fill" }
    };
    document.querySelectorAll(".flash-area .alert").forEach(function (alertEl, idx) {
      var cat = alertEl.getAttribute("data-flash-category") || "dark";
      var style = CATEGORY_STYLE[cat] || CATEGORY_STYLE.dark;
      var toast = document.createElement("div");
      toast.className = "toast align-items-center border-0 show mb-2 " + style.bg;
      toast.setAttribute("role", "alert");
      toast.setAttribute("aria-live", "assertive");
      toast.setAttribute("aria-atomic", "true");
      toast.innerHTML =
        '<div class="d-flex">' +
        '  <div class="toast-body d-flex align-items-start gap-2">' +
        '    <i class="bi ' + style.icon + ' mt-1"></i><span>' + alertEl.firstChild.textContent.trim() + '</span>' +
        '  </div>' +
        '  <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>' +
        '</div>';
      toastArea.appendChild(toast);
      new bootstrap.Toast(toast, { delay: 6000 }).show();
      // Keep a plain (hidden) copy for no-JS/print contexts
      alertEl.classList.add("visually-hidden");
    });

    /* ---------- Generic delete confirmation modal ----------
       Any element with [data-confirm-url] opens #confirmModal and its
       inner form posts to the given URL. Optional data-confirm-title /
       data-confirm-text customise the message. */
    var confirmModal = document.getElementById("confirmModal");
    if (confirmModal) {
      var modalForm = confirmModal.querySelector("form");
      var modalTitle = confirmModal.querySelector(".modal-title");
      var modalBody = confirmModal.querySelector(".modal-body p");
      confirmModal.addEventListener("show.bs.modal", function (event) {
        var trigger = event.relatedTarget;
        if (!trigger) return;
        modalForm.setAttribute("action", trigger.getAttribute("data-confirm-url"));
        modalTitle.textContent = trigger.getAttribute("data-confirm-title") || "Are you sure?";
        modalBody.textContent = trigger.getAttribute("data-confirm-text") ||
          "This action cannot be undone.";
      });
    }

    /* ---------- Print buttons ---------- */
    document.querySelectorAll("[data-print]").forEach(function (btn) {
      btn.addEventListener("click", function () { window.print(); });
    });

    /* ---------- Auto-dismiss plain alerts after 6s (non-blocking) ---------- */
    // Kept intentionally: alerts remain visible; toasts handle notifications.

  });
})();
