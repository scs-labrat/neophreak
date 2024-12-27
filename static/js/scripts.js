document.getElementById("uploadForm").onsubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData();
    formData.append("file", document.getElementById("fileInput").files[0]);

    const response = await fetch("/upload", { method: "POST", body: formData });
    const result = await response.json();
    const filepath = result.filepath;

    const mode = document.getElementById("mode").value;
    const msisdn = document.getElementById("msisdn").value;

    const startTests = await fetch("/run_tests", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filepath, mode, msisdn })
    });

    const message = await startTests.json();
    console.log(message);
};