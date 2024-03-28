const express = require("express");
const router = express.Router();
const blogController = require("../controllers/blog.controller.js");

const { protect, protectAdmin } = require("../middleware/protect.js");

router.get("/", blogController.getBlogs);
router.get("/:id",blogController.getBlogById);
router.post("/", blogController.createBlog);
router.put("/:id", blogController.updateBlog);
router.delete("/:id",blogController.deleteBlog);

module.exports = router