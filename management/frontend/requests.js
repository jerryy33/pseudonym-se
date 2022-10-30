const BACKEND_HOST = "http://localhost:8080"
export async function enrollUser(userID) {
    console.log(userID)
    const response = await fetch(`${BACKEND_HOST}/enroll/${userID}`, { method: "POST" })
    if (response.ok) {
        const enrollResponse = await response.json()
        document.getElementById("results").innerText = "Enrollment was successfull: " + enrollResponse;
    }
    else {
        const errorDetail = await response.text()
        document.getElementById("results").innerText = response.statusText + errorDetail
    }
}
export async function revokeUser(userID) {
    const response = await fetch(`${BACKEND_HOST}/revoke?user_id=${userID}`, { method: "POST" })
    if (response.ok) {
        const revokeResponse = await response.json()
        document.getElementById("results").innerText = "Revokation was successfull: " + revokeResponse;
    }
    else {
        const errorDetail = await response.text()
        document.getElementById("results").innerText = response.statusText + errorDetail
    }
}

export async function setup() {
    const response = await fetch(`${BACKEND_HOST}/setup`, { method: "POST" })
    if (response.ok) {
        const setupResponse = await response.json()
        document.getElementById("setup-results").innerText = "Setup was successfull: " + setupResponse
    }
    else {
        const errorDetail = await response.text()
        document.getElementById("setup-results").innerText = response.statusText + errorDetail
    }
}