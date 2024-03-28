const express = require("express");
const router = express.Router();
const bannerController = require("../controllers/banner.controller.js");
const { protect, protectAdmin } = require("../middleware/protect.js");

router.get("/", bannerController.getBanners);
router.get("/:id", bannerController.getBannerById);
router.post("/",bannerController.createBanner);
router.patch("/:id",bannerController.updateBanner);
router.delete("/:id",bannerController.deleteBanner);

module.exports = router