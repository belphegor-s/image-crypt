require("dotenv").config();
const express = require("express");
const multer = require("multer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const app = express();
const port = process.env.PORT ?? 9191;

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = "./uploads";
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir);
        }
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    },
});

const upload = multer({ storage: storage });

app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));
app.use(express.json());

function encryptImage(inputPath, outputPath, password) {
    return new Promise((resolve, reject) => {
        fs.readFile(inputPath, (err, imageBuffer) => {
            if (err) return reject(err);

            const key = crypto.scryptSync(password, "salt", 32);
            const iv = crypto.randomBytes(16);

            const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);

            const encryptedImage = Buffer.concat([iv, cipher.update(imageBuffer), cipher.final()]);

            fs.writeFile(outputPath, encryptedImage, (err) => {
                if (err) return reject(err);
                resolve(outputPath);
            });
        });
    });
}

function decryptImage(inputPath, outputPath, password) {
    return new Promise((resolve, reject) => {
        fs.readFile(inputPath, (err, encryptedBuffer) => {
            if (err) return reject(err);

            try {
                const iv = encryptedBuffer.subarray(0, 16);
                const encryptedImage = encryptedBuffer.subarray(16);

                const key = crypto.scryptSync(password, "salt", 32);

                const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);

                const decryptedImage = Buffer.concat([decipher.update(encryptedImage), decipher.final()]);

                fs.writeFile(outputPath, decryptedImage, (err) => {
                    if (err) return reject(err);
                    resolve(outputPath);
                });
            } catch (error) {
                reject("Decryption failed. Check if password is correct.");
            }
        });
    });
}

app.post("/encrypt", upload.single("image"), async (req, res) => {
    if (!req.file || !req.body.password) {
        return res.status(400).json({ error: "Image and password are required" });
    }

    const inputPath = req.file.path;
    const outputPath = `./uploads/encrypted_${path.basename(req.file.path)}`;

    try {
        const result = await encryptImage(inputPath, outputPath, req.body.password);
        res.json({
            success: true,
            originalImage: req.file.path,
            encryptedImage: result,
            message: "Image encrypted successfully",
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post("/decrypt", upload.single("image"), async (req, res) => {
    if (!req.file || !req.body.password) {
        return res.status(400).json({ error: "Encrypted image and password are required" });
    }

    const inputPath = req.file.path;
    const outputPath = `./uploads/decrypted_${path.basename(req.file.path)}`;

    try {
        const result = await decryptImage(inputPath, outputPath, req.body.password);
        res.json({
            success: true,
            encryptedImage: req.file.path,
            decryptedImage: result,
            message: "Image decrypted successfully",
        });
    } catch (error) {
        res.status(500).json({ error: error.message || "Decryption failed" });
    }
});

app.listen(port, () => {
    console.log(`Image encryption server running at http://localhost:${port}`);
});
