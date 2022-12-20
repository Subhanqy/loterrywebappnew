// JavaScript function to generate 6 random unique values in order and populate form.
function luckyDip() {

    // Create empty set.
    let values = new Set();

    // floatarray[0] = randomBuffer[0]
    // float[0] = floatArray[0] / (0xFFFFFFFFF)
    // csRandomNumber = floatArray[0]

    // While set does not contain 6 values, create a random value between 1 and 60.
    while (values.size < 6) {
        // Create a typed array of 32-bit unsigned integers with a length of 1 element initialised as 0.
        let randomBuffer = new Uint32Array(1);
        // Fill the array with cryptographically strong random values.
        window.crypto.getRandomValues(randomBuffer);
        // Divide the value held in array by 32-bit unsigned integer max value to get a floating point number.
        let randomNumber = randomBuffer[0] / (0xFFFFFFFF);
        let min = Math.ceil(1);
        let max = Math.floor(60);
        // Convert random number float to an integer between min and max.
        let value = Math.floor(randomNumber * (max - min + 1)) + min;

        // Sets cannot contain duplicates so value is only added if it does not exist in set.
        values.add(value)
    }

    // Turn set into an array.
    let a = Array.from(values);

    // Sort array into size order.
    a.sort(function (a, b) {
        return a - b;
    });

    // Add values to fields in create draw form.
    for (let i = 0; i < 6; i++) {
        document.getElementById("no" + (i + 1)).value = a[i];
    }
}