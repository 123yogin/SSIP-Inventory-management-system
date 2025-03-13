function editProfile() {
    let newName = prompt("Enter new name:", document.getElementById("employee-name").innerText);
    let newJobTitle = prompt("Enter new job title:", document.getElementById("job-title").innerText);
    let newDepartment = prompt("Enter new department:", document.getElementById("department").innerText);
    let newEmployeeID = prompt("Enter new Employee ID:", document.getElementById("employee-id").innerText);
    let newJoiningDate = prompt("Enter new Joining Date:", document.getElementById("joining-date").innerText);

    if (newName) document.getElementById("employee-name").innerText = newName;
    if (newJobTitle) document.getElementById("job-title").innerText = newJobTitle;
    if (newDepartment) document.getElementById("department").innerText = newDepartment;
    if (newEmployeeID) document.getElementById("employee-id").innerText = newEmployeeID;
    if (newJoiningDate) document.getElementById("joining-date").innerText = newJoiningDate;
}