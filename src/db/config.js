import mongoose from "mongoose";
const URI =
  "mongodb+srv://nahueldimuro:pumadk@clusterdimuro.ir5auko.mongodb.net/ecommerceCH?retryWrites=true&w=majority";

mongoose
  .connect(URI)
  .then(() => console.log("conexion establecida en bd"))
  .catch((error) => console.log(error));
