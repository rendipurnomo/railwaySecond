const express = require("express");
const router = express.Router();
const productController = require("../controllers/product.controller.js");
const { protect, protectAdmin } = require("../middleware/protect.js");

router.get("/", productController.getProducts);
router.get("/:id", productController.getProductById);
router.post("/", productController.createProduct);
router.patch("/:id", productController.updateProduct);
router.delete("/:id",productController.deleteProduct);

module.exports = router