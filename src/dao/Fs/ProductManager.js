import fs from "fs";

class ProductManager {
  constructor(path) {
    this.path = path;
  }

  async getProducts(queryObj) {
    const { limit } = queryObj;
    try {
      if (fs.existsSync(this.path)) {
        const info = await fs.promises.readFile(this.path, "utf-8");
        const arrayObj = JSON.parse(info);
        return limit ? arrayObj.slice(0, limit) : arrayObj;
      } else {
        return [];
      }
    } catch (error) {
      return error;
    }
  }

  async addProduct(product) {
    try {
      const products = await this.getProducts({});
      const codeRepeat = products.find((p) => p.code === product.code);

      if (
        !product.title ||
        !product.description ||
        !product.price

      ) {
        console.log("Faltan campos");
        return;
      }
      let id;

      if (!products.length) {
        id = 1;
      } else {
        id = products[products.length - 1].id + 1;
      }

      products.push({ id, ...product });

      await fs.promises.writeFile(this.path, JSON.stringify(products));
    } catch (error) {
      return error;
    }
  }

  async getProductById(idProd) {
    try {
      const prods = await this.getProducts({});
      console.log("prods", prods);
      const prod = prods.find((p) => p.id === idProd);
      return prod;
    } catch (error) {
      return error;
    }
  }
  async updateProduct(idProd, obj) {
    try {
      const prods = await this.getProducts({});
      const modifProd = prods.findIndex((p) => p.id === idProd);
      if (modifProd === -1) {
        return -1;
      }
      const prod = prods[modifProd];
      prods[modifProd] = { ...prod, ...obj };
      await fs.promises.writeFile(this.path, JSON.stringify(prods));
      return 1;
    } catch (error) {
      return error;
    }
  }

  async deleteProduct(idProd) {
    try {
      const prods = await this.getProducts({});
      const deletedProd = prods.find((p) => p.id === idProd);
      console.log(deletedProd);
      if (!deletedProd) {
        return -1;
      }
      const product = prods.filter((p) => p.id !== idProd);

      await fs.promises.writeFile(this.path, JSON.stringify(product));
      return 1;
    } catch (error) {
      return error;
    }
  }
}


export default new ProductManager("products.json");
