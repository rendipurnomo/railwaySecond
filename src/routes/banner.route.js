const express = require("express");
const router = express.Router();
const bannerController = require("../controllers/banner.controller.js");
const { protect, protectAdmin } = require("../middleware/protect.js");

router.get("/", bannerController.getBanners);
router.post("/", protect, protectAdmin, bannerController.createBanner);
router.patch("/:id", protect, protectAdmin, bannerController.updateBanner);
router.delete("/:id", protect, protectAdmin, bannerController.deleteBanner);

module.exports = router