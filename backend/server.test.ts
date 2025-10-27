// tests/server.test.js
import request from 'supertest';
import { app, pool } from './server.ts'; // import your Express app instance and database pool

beforeAll(async () => {
  // Run any setup tasks like seeding a test database
});

afterAll(async () => {
  await pool.end();  // Close the DB pool at the end of all tests
});

describe("User API Endpoints", () => {
  describe("GET /users", () => {
    it("should return a list of users", async () => {
      const response = await request(app).get("/users");
      expect(response.statusCode).toBe(200);
      expect(Array.isArray(response.body)).toBeTruthy();
    });

    it("should require authentication", async () => {
      // Assuming the endpoint should fail without an auth token
      const response = await request(app).get("/users").set("Authorization", "");  // No token provided
      expect(response.statusCode).toBe(401);
    });
  });

  describe("GET /users/:user_id", () => {
    it("should return a user's details", async () => {
      const response = await request(app).get("/users/123");
      expect(response.statusCode).toBe(200);
      expect(response.body).toHaveProperty('uid', '123');
    });

    it("should return 404 for non-existent user", async () => {
      const response = await request(app).get("/users/nonexistent");
      expect(response.statusCode).toBe(404);
    });
  });
});

describe("Product API Endpoints", () => {
  describe("GET /products", () => {
    it("should return a list of products", async () => {
      const response = await request(app).get("/products");
      expect(response.statusCode).toBe(200);
      expect(Array.isArray(response.body)).toBeTruthy();
    });
  });

  describe("POST /products", () => {
    it("should create a new product", async () => {
      const newProduct = {
        title: "New Product",
        price: 9.99,
        in_stock: true
      };
      const response = await request(app).post("/products").send(newProduct).set("Authorization", "ValidAdminToken");
      expect(response.statusCode).toBe(201);
      expect(response.body).toHaveProperty('title', newProduct.title);
    });

    it("should not allow creation without auth", async () => {
      const newProduct = { title: "NoAuthProduct", price: 19.99, in_stock: true };
      const response = await request(app).post("/products").send(newProduct);
      expect(response.statusCode).toBe(403);
    });
  });

  describe("PUT /products/:product_id", () => {
    it("should update an existing product", async () => {
      const productUpdates = { price: 24.99, in_stock: false };
      const response = await request(app).put("/products/123").send(productUpdates).set("Authorization", "ValidAdminToken");
      expect(response.statusCode).toBe(200);
      expect(response.body).toHaveProperty('price', productUpdates.price);
    });

    it("should return 404 for non-existent product update", async () => {
      const productUpdates = { price: 34.99, in_stock: false };
      const response = await request(app).put("/products/nonexistent").send(productUpdates).set("Authorization", "ValidAdminToken");
      expect(response.statusCode).toBe(404);
    });
  });

  describe("DELETE /products/:product_id", () => {
    it("should delete a product", async () => {
      const response = await request(app).delete("/products/123").set("Authorization", "ValidAdminToken");
      expect(response.statusCode).toBe(204);
    });

    it("should return 404 for deleting non-existent product", async () => {
      const response = await request(app).delete("/products/nonexistent").set("Authorization", "ValidAdminToken");
      expect(response.statusCode).toBe(404);
    });
  });
});