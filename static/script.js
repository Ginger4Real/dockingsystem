document.addEventListener("DOMContentLoaded", () => {
  const dockForm = document.getElementById("dock-form");
  const clearForm = document.getElementById("clear-form");
  const notification = document.getElementById("notification");

  // Function to show notifications
  function showNotification(message, type) {
    notification.textContent = message;
    notification.className = `notification ${type} show`;
    setTimeout(() => {
      notification.classList.remove("show");
    }, 3000);
  }

  // Populate docks in select elements
  function populateDocks(docks) {
    const dockSelect = document.getElementById("dock-number");
    const clearDockSelect = document.getElementById("clear-dock-number");

    dockSelect.innerHTML =
      '<option value="" disabled selected>Select a dock</option>';
    clearDockSelect.innerHTML =
      '<option value="" disabled selected>Select a dock</option>';

    docks.forEach((dock) => {
      const option = document.createElement("option");
      option.value = dock.number;
      option.textContent = `Dock ${dock.number}`;
      dockSelect.appendChild(option);
      clearDockSelect.appendChild(option.cloneNode(true));
    });
  }

  // Handle dock assignment
  dockForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const licensePlate = document.getElementById("license-plate").value;
    const dockNumber = document.getElementById("dock-number").value;

    fetch("/assign-dock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        license_plate: licensePlate,
        dock_number: dockNumber,
      }),
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          showNotification("Dock assigned successfully!", "success");
          updateDockList();
        } else {
          showNotification(data.message, "error");
        }
      });
  });

  // Handle dock clearing
  clearForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const dockNumber = document.getElementById("clear-dock-number").value;

    fetch("/clear-dock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ dock_number: dockNumber }),
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          showNotification("Dock cleared successfully!", "success");
          updateDockList();
        } else {
          showNotification(data.message, "error");
        }
      });
  });

  // Function to update dock list
  function updateDockList() {
    fetch("/docks")
      .then((response) => response.json())
      .then((data) => {
        const dockList = document.getElementById("dock-list");
        dockList.innerHTML = "";
        data.docks.forEach((dock) => {
          const listItem = document.createElement("li");
          listItem.textContent = dock.license_plate
            ? `Dock ${dock.number}: ${dock.license_plate}`
            : `Dock ${dock.number}: Empty`;
          dockList.appendChild(listItem);
        });
        populateDocks(data.docks);
      });
  }

  // Initial dock list update
  updateDockList();
});
