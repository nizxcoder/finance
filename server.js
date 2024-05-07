const express = require("express");
const dbConnect = require("./Config/db");
const bodyParser = require("body-parser");
const app = express();
require("dotenv").config();
const PORT = process.env.PORT;

app.set("view engine", "ejs");
app.use(express.json());
app.use(bodyParser.json());

dbConnect().then(() => {
  app.use("/user", require("./Routes/handleUser"));

  app.get("/", (req, res) => {
    res.send("Hello World!");
  });
  app.get("/error", (req, res) => {
    throw new Error("This is an error");
  });

  app.use(function errorHandler(err, req, res, next) {
    if (res.headersSent) {
      return next(err);
    }
    res.status(500).render("error", { error: err }); // Send error response here
  });
  app.listen(PORT, () => {
    console.log("Server is running on", { PORT });
  });
});
