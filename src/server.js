const express = require("express")
const fileUpload = require("express-fileupload")
const cookieParser = require("cookie-parser")
const userRoute = require("./routes/user.route.js")
const authRoute = require("./routes/auth.route.js")
const productRoute = require("./routes/product.route.js")
const orderRoute = require("./routes/order.route.js")
const bannerRoute = require("./routes/banner.route.js")
const blogRoute = require("./routes/blog.route.js")
const cors = require("cors")

const dotenv = require("dotenv")
dotenv.config()
const PORT = process.env.PORT

const app = express()

app.use(express.json())
app.use(cookieParser())
app.use(fileUpload())
app.use(express.static('src/public'))
app.use(cors())


app.use("/api/users", userRoute)
app.use("/api/auth", authRoute)
app.use("/api/products", productRoute)
app.use("/api/orders", orderRoute)
app.use("/api/banners", bannerRoute)
app.use("/api/blogs", blogRoute)

app.get("/", (req, res) => {
  res.json({ message: "Server is up and running" })
})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
