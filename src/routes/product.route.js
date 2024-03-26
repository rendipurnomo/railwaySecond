const express = require("express");
const router = express.Router();
const productController = require("../controllers/product.controller.js");
const { protect, protectAdmin } = require("../middleware/protect.js");

router.get("/", protect, productController.getProducts);
router.get("/:id", productController.getProductById);
router.post("/", protect, protectAdmin, productController.createProduct);
router.patch("/:id", protect, protectAdmin, productController.updateProduct);
router.delete("/:id", protect, protectAdmin, productController.deleteProduct);

module.exports = router