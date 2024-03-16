# express.js-coding-round
<h1> Here are 50 coding questions related to Express.js for a job interview, along with their answers:</h1>

1. **Creating a Basic Express Server:**

   **Question:** Write a code snippet to create a basic Express server listening on port 3000.

   **Answer:**
   ```javascript
   const express = require('express');
   const app = express();

   app.listen(3000, () => {
       console.log('Server is running on port 3000');
   });
   ```

2. **Defining a Route:**

   **Question:** Write a route to handle GET requests to '/hello' and respond with 'Hello, World!'.

   **Answer:**
   ```javascript
   app.get('/hello', (req, res) => {
       res.send('Hello, World!');
   });
   ```

3. **Handling POST Requests:**

   **Question:** Create a route to handle POST requests to '/submit' and log the request body to the console.

   **Answer:**
   ```javascript
   app.post('/submit', (req, res) => {
       console.log(req.body);
       res.send('Data received');
   });
   ```

4. **Middleware:**

   **Question:** Define a middleware function that logs the request method and URL for each incoming request.

   **Answer:**
   ```javascript
   app.use((req, res, next) => {
       console.log(`${req.method} ${req.url}`);
       next();
   });
   ```

5. **Handling Route Parameters:**

   **Question:** Write a route to handle GET requests to '/users/:id' and respond with the user ID.

   **Answer:**
   ```javascript
   app.get('/users/:id', (req, res) => {
       res.send(`User ID: ${req.params.id}`);
   });
   ```

6. **Handling Query Parameters:**

   **Question:** Create a route to handle GET requests to '/search' and respond with the value of the 'q' query parameter.

   **Answer:**
   ```javascript
   app.get('/search', (req, res) => {
       res.send(`Search query: ${req.query.q}`);
   });
   ```

7. **Serving Static Files:**

   **Question:** Serve static files located in the 'public' directory.

   **Answer:**
   ```javascript
   app.use(express.static('public'));
   ```

8. **Using Router:**

   **Question:** Create a router to handle routes related to authentication (e.g., login, logout).

   **Answer:**
   ```javascript
   const authRouter = require('./routes/auth');
   app.use('/auth', authRouter);
   ```

9. **Error Handling Middleware:**

   **Question:** Define an error-handling middleware function that logs errors to the console.

   **Answer:**
   ```javascript
   app.use((err, req, res, next) => {
       console.error(err);
       res.status(500).send('Internal Server Error');
   });
   ```

10. **Route Chaining:**

    **Question:** Define multiple route handlers for the same route '/profile', each handling different HTTP methods.

    **Answer:**
    ```javascript
    app.route('/profile')
       .get((req, res) => {
           // Handle GET request
       })
       .post((req, res) => {
           // Handle POST request
       });
    ```

11. **Custom Middleware:**

    **Question:** Write a middleware function that checks if the user is authenticated and redirects to the login page if not.

    **Answer:**
    ```javascript
    function authenticate(req, res, next) {
        if (!req.user) {
            res.redirect('/login');
        } else {
            next();
        }
    }
    ```

12. **File Upload:**

    **Question:** Implement a route to handle file uploads and save the uploaded file to the server.

    **Answer:**
    ```javascript
    const multer = require('multer');
    const upload = multer({ dest: 'uploads/' });

    app.post('/upload', upload.single('file'), (req, res) => {
        // File uploaded successfully
        res.send('File uploaded');
    });
    ```

13. **Session Management:**

    **Question:** Configure Express to use session middleware for managing user sessions.

    **Answer:**
    ```javascript
    const session = require('express-session');
    app.use(session({ secret: 'secret-key', resave: false, saveUninitialized: true }));
    ```

14. **Redirecting:**

    **Question:** Create a route to redirect requests from '/old' to '/new'.

    **Answer:**
    ```javascript
    app.get('/old', (req, res) => {
        res.redirect('/new');
    });
    ```

15. **JSON Response:**

    **Question:** Define a route to send a JSON response with user data.

    **Answer:**
    ```javascript
    app.get('/user', (req, res) => {
        res.json({ name: 'John', age: 30 });
    });
    ```

16. **Using External Middleware:**

    **Question:** Install and use the 'cors' middleware to enable CORS in your Express application.

    **Answer:**
    ```javascript
    const cors = require('cors');
    app.use(cors());
    ```

17. **View Rendering:**

    **Question:** Configure Express to use the 'ejs' template engine for rendering views.

    **Answer:**
    ```javascript
    app.set('view engine', 'ejs');
    ```

18. **Cookie Parsing:**

    **Question:** Use the 'cookie-parser' middleware to parse cookies in incoming requests.

    **Answer:**
    ```javascript
    const cookieParser = require('cookie-parser');
    app.use(cookieParser());
    ```

19. **Session Authentication:**

    **Question:** Implement session-based authentication using Express session middleware.

    **Answer:**
    ```javascript
    app.use((req, res, next) => {
        if (req.session && req.session.user) {
            // User is authenticated
            next();
        } else {
            res.redirect('/login');
        }
    });
    ```

20. **Using Express Router:**

    **Question:** Create a router to handle routes related to user profile management (e.g., edit, delete).

    **Answer:**
    ```javascript
    const profileRouter = require('./routes/profile');
    app.use('/profile', profileRouter);
    ```

21. **Form Validation:**

    **Question:** Implement server-side form validation middleware to validate form data before processing it.

    **Answer:**
    ```javascript
    function validateForm(req, res, next) {
        if (!req.body.username || !req.body.password) {
            res.status(400).send('Username and password are required');
        } else {
            next();
        }
    }
    ```

22. **Using External Modules:**

    **Question:** Install and use the 'bcrypt' module to hash passwords before storing them in the database.

    **Answer:**
    ```javascript
    const bcrypt = require('bcrypt');
    ```

23. **Handling PUT Requests:**

    **Question:** Create a route to handle PUT requests to update user data.

    **Answer:**
   

 ```javascript
    app.put('/user/:id', (req, res) => {
        // Update user data
        res.send('User data updated');
    });
    ```

24. **Using Express Generator:**

    **Question:** Generate a new Express application using the Express generator tool.

    **Answer:**
    ```
    $ npm install -g express-generator
    $ express myapp
    ```

25. **Using External Databases:**

    **Question:** Install and use the 'mongoose' module to connect to a MongoDB database in your Express application.

    **Answer:**
    ```javascript
    const mongoose = require('mongoose');
    mongoose.connect('mongodb://localhost/myapp', { useNewUrlParser: true, useUnifiedTopology: true });
    ```

26. **Middleware to Check Authentication:**

    **Question:** Write a middleware function to check if a user is logged in and has admin privileges.

    **Answer:**
    ```javascript
    function isAdmin(req, res, next) {
        if (req.user && req.user.isAdmin) {
            next();
        } else {
            res.status(403).send('Forbidden');
        }
    }
    ```

27. **File Download:**

    **Question:** Implement a route to allow users to download a file from the server.

    **Answer:**
    ```javascript
    app.get('/download/:filename', (req, res) => {
        const filename = req.params.filename;
        res.download(`./uploads/${filename}`);
    });
    ```

28. **Logging Middleware:**

    **Question:** Write a middleware function to log request details to a file.

    **Answer:**
    ```javascript
    const fs = require('fs');
    app.use((req, res, next) => {
        fs.appendFileSync('request.log', `${req.method} ${req.url}\n`);
        next();
    });
    ```

29. **Handling DELETE Requests:**

    **Question:** Create a route to handle DELETE requests to delete user data.

    **Answer:**
    ```javascript
    app.delete('/user/:id', (req, res) => {
        // Delete user data
        res.send('User data deleted');
    });
    ```

30. **Authentication Middleware:**

    **Question:** Write a middleware function to authenticate users using JSON Web Tokens (JWT).

    **Answer:**
    ```javascript
    const jwt = require('jsonwebtoken');
    function authenticate(req, res, next) {
        const token = req.headers.authorization;
        if (token) {
            jwt.verify(token, 'secret-key', (err, decoded) => {
                if (err) {
                    res.status(401).send('Unauthorized');
                } else {
                    req.user = decoded;
                    next();
                }
            });
        } else {
            res.status(401).send('Unauthorized');
        }
    }
    ```

31. **Handling PATCH Requests:**

    **Question:** Create a route to handle PATCH requests to update specific fields of user data.

    **Answer:**
    ```javascript
    app.patch('/user/:id', (req, res) => {
        // Update specific fields of user data
        res.send('User data updated');
    });
    ```

32. **Pagination Middleware:**

    **Question:** Write a middleware function to implement pagination for query results.

    **Answer:**
    ```javascript
    function paginate(req, res, next) {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const startIndex = (page - 1) * limit;
        const endIndex = page * limit;

        req.pagination = {
            page: page,
            limit: limit,
            startIndex: startIndex,
            endIndex: endIndex
        };
        next();
    }
    ```

33. **Rate Limiting Middleware:**

    **Question:** Implement rate limiting middleware to limit the number of requests per IP address.

    **Answer:**
    ```javascript
    const rateLimit = require('express-rate-limit');
    const limiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100 // limit each IP to 100 requests per windowMs
    });
    app.use(limiter);
    ```

34. **CRUD Operations with MongoDB:**

    **Question:** Write a route to handle CRUD operations for a 'users' collection in a MongoDB database.

    **Answer:**
    ```javascript
    const User = require('./models/user');
    // Create
    app.post('/users', (req, res) => {
        const user = new User(req.body);
        user.save()
            .then(result => {
                res.json(result);
            })
            .catch(err => {
                res.status(400).send(err);
            });
    });
    // Read
    app.get('/users/:id', (req, res) => {
        User.findById(req.params.id)
            .then(user => {
                res.json(user);
            })
            .catch(err => {
                res.status(404).send('User not found');
            });
    });
    // Update
    app.put('/users/:id', (req, res) => {
        User.findByIdAndUpdate(req.params.id, req.body, { new: true })
            .then(user => {
                res.json(user);
            })
            .catch(err => {
                res.status(404).send('User not found');
            });
    });
    // Delete
    app.delete('/users/:id', (req, res) => {
        User.findByIdAndDelete(req.params.id)
            .then(user => {
                res.json(user);
            })
            .catch(err => {
                res.status(404).send('User not found');
            });
    });
    ```

35. **Handling File Uploads with Multer:**

    **Question:** Implement a route to handle file uploads using Multer middleware and store uploaded files in the 'uploads' directory.

    **Answer:**
    ```javascript
    const multer = require('multer');
    const storage = multer.diskStorage({
        destination: (req, file, cb) => {
            cb(null, 'uploads/');
        },
        filename: (req, file, cb) => {
            cb(null, Date.now() + '-' + file.originalname);
        }
    });
    const upload = multer({ storage: storage });

    app.post('/upload', upload.single('file'), (req, res) => {
        res.send('File uploaded successfully');
    });
    ```

36. **Handling JSON Web Tokens (JWT):**

    **Question:** Create a route to handle user authentication using JWT.

    **Answer:**
    ```javascript
    const jwt = require('jsonwebtoken');

    app.post('/login', (req, res) => {
        // Authenticate user
        const user = { id: 1, username: 'user' };
        const token = jwt.sign(user, 'secret-key');
        res.json({ token: token });
    });

    app.get('/protected', (req, res) => {
        jwt.verify(req.headers.authorization, 'secret-key', (err, decoded) => {
            if (err) {
                res.status(401).send('Unauthorized');
            } else {
                res.json(decoded);
            }
        });
    });
  <h2> Here are 5 coding practice questions specifically tailored for cracking interviews related to Express.js: </h2>

1. **Middleware Implementation**:

**Question**: Write a custom middleware function in Express.js that logs the timestamp of incoming requests along with the request method and URL.

**Solution**:
```javascript
const express = require('express');
const app = express();

app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

// Define your routes here

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
```

2. **Route Parameter Handling**:

**Question**: Create an Express.js route that accepts a product ID as a parameter and responds with the details of that product from a predefined array of products.

**Solution**:
```javascript
const express = require('express');
const app = express();

const products = [
    { id: 1, name: 'Product A', price: 10 },
    { id: 2, name: 'Product B', price: 20 },
    { id: 3, name: 'Product C', price: 30 }
];

app.get('/product/:id', (req, res) => {
    const productId = parseInt(req.params.id);
    const product = products.find(p => p.id === productId);
    if (product) {
        res.json(product);
    } else {
        res.status(404).json({ error: 'Product not found' });
    }
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
```

3. **File Upload Endpoint**:

**Question**: Implement an Express.js route for handling file uploads. The endpoint should accept files and save them to a predefined directory on the server.

**Solution**:
```javascript
const express = require('express');
const multer = require('multer');
const app = express();
const upload = multer({ dest: 'uploads/' });

app.post('/upload', upload.single('file'), (req, res) => {
    res.send('File uploaded successfully');
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
```

4. **Authentication Middleware**:

**Question**: Develop an Express.js middleware function that checks for a valid authentication token in the request headers. If the token is missing or invalid, it should respond with a 401 Unauthorized status.

**Solution**:
```javascript
const express = require('express');
const app = express();

const authenticate = (req, res, next) => {
    const token = req.headers.authorization;
    if (token === 'valid_token') {
        next();
    } else {
        res.status(401).send('Unauthorized');
    }
};

app.get('/secure', authenticate, (req, res) => {
    res.send('Access granted');
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
```

5. **Error Handling Middleware**:

**Question**: Write an error-handling middleware function in Express.js that catches any unhandled errors in the application and responds with a 500 Internal Server Error status along with an error message.

**Solution**:
```javascript
const express = require('express');
const app = express();

app.get('/error', (req, res, next) => {
    try {
        // Code that may throw an error
        throw new Error('Oops! Something went wrong');
    } catch (error) {
        next(error); // Pass the error to the error-handling middleware
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Internal Server Error');
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
````


<h3> here are 30 express js question</h3>


1. **File Upload Endpoint Answer**:
```javascript
const express = require('express');
const multer = require('multer');
const app = express();
const upload = multer({ dest: 'uploads/' });

app.post('/upload', upload.single('file'), (req, res) => {
    res.send('File uploaded successfully');
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
```

2. **JWT Authentication Middleware Answer**:
```javascript
const jwt = require('jsonwebtoken');

const authenticate = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ error: 'Token required' });
    }
    try {
        const decoded = jwt.verify(token, 'your_secret_key');
        req.user = decoded.user;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};
```

3. **Pagination Middleware Answer**:
```javascript
const paginate = (req, res, next) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;
    const results = {};

    if (endIndex < data.length) {
        results.next = {
            page: page + 1,
            limit: limit
        };
    }

    if (startIndex > 0) {
        results.previous = {
            page: page - 1,
            limit: limit
        };
    }

    results.data = data.slice(startIndex, endIndex);

    res.paginatedData = results;
    next();
};
```

4. **User Registration Endpoint Answer**:
```javascript
app.post('/register', (req, res) => {
    // Handle user registration logic here
});
```

5. **Password Encryption Utility Answer**:
```javascript
const bcrypt = require('bcrypt');

const hashPassword = async (password) => {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
};
```

6. **User Login Endpoint Answer**:
```javascript
app.post('/login', (req, res) => {
    // Handle user login logic here
});
```

7. **Route-Level Authorization Middleware Answer**:
```javascript
const authorize = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        next();
    };
};
```

8. **Error Handling Middleware Answer**:
```javascript
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Internal Server Error');
});
```

9. **RESTful Todo List API Answer**:
```javascript
// Define routes for CRUD operations
```

10. **Email Verification Endpoint Answer**:
```javascript
app.get('/verify-email/:token', (req, res) => {
    // Handle email verification logic here
});
```

11. **Custom Response Formatting Middleware Answer**:
```javascript
const formatResponse = (req, res, next) => {
    res.sendFormattedResponse = (data, statusCode) => {
        res.status(statusCode || 200).json({ success: true, data: data });
    };
    next();
};
```

12. **Password Reset Endpoint Answer**:
```javascript
app.post('/reset-password', (req, res) => {
    // Handle password reset logic here
});
```

13. **Static File Serving Middleware Answer**:
```javascript
app.use(express.static('public'));
```

14. **Database Connection Middleware Answer**:
```javascript
const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/your_database', { useNewUrlParser: true, useUnifiedTopology: true });
```

15. **Request Timeout Middleware Answer**:
```javascript
const requestTimeout = (req, res, next) => {
    req.setTimeout(5000, () => {
        res.status(408).send('Request Timeout');
    });
    next();
};
```

16. **Rate Limiting Middleware Answer**:
```javascript
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});

app.use(limiter);
```

17. **Image Upload API Answer**:
```javascript
// Use Multer middleware for handling file uploads
```

18. **Cross-Origin Resource Sharing (CORS) Middleware Answer**:
```javascript
const cors = require('cors');
app.use(cors());
```

19. **GraphQL Endpoint Answer**:
```javascript
// Use Apollo Server for serving GraphQL queries
```

20. **Two-Factor Authentication Endpoint Answer**:
```javascript
app.post('/verify-otp', (req, res) => {
    // Handle OTP verification logic here
});
```

21. **Server-Sent Events (SSE) Endpoint Answer**:
```javascript
app.get('/sse', (req, res) => {
    // Implement SSE logic here
});
```

22. **Web Scraping Endpoint Answer**:
```javascript
app.get('/scrape', (req, res) => {
    // Implement web scraping logic here
});
```

23. **Session Management Middleware Answer**:
```javascript
const session = require('express-session');
app.use(session({ secret: 'your_secret', resave: true, saveUninitialized: true }));
```

24. **Websocket Integration Middleware Answer**:
```javascript
const http = require('http');
const server = http.createServer(app);
const io = require('socket.io')(server);
```

25. **IP Filtering Middleware Answer**:
```javascript
const ipFilter = (req, res, next) => {
    // Implement IP filtering logic here
};
```

26. **Health Check Endpoint Answer**:
```javascript
app.get('/health', (req, res) => {
    res.send('Server is running');
});
```

27. **Proxy Middleware Answer**:
```javascript
const httpProxy = require('http-proxy');
const proxy = httpProxy.createProxyServer();

app.use('/api', (req, res) => {
    proxy.web(req, res, { target: 'http://example.com' });
});
```

28. **Authentication with OAuth Endpoint Answer**:
```javascript
// Use passport.js for OAuth authentication
```

29. **Data Validation Middleware Answer**:
```javascript
const Joi = require('joi');

const validateData = (schema) => {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }
        next();
    };
};
```

30. **Custom Error Handling Middleware Answer**:
```javascript
const errorHandler = (err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Internal Server Error');
};
app.use(errorHandler);
```




1. **Create a basic Express.js server that listens on port 3000.**

   ```javascript
   const express = require('express');
   const app = express();

   app.listen(3000, () => {
       console.log('Server is running on port 3000');
   });
   ```

   - This code snippet creates an Express.js server and listens on port 3000.

2. **Implement a route in Express.js to handle GET requests.**

   ```javascript
   app.get('/', (req, res) => {
       res.send('Hello, World!');
   });
   ```

   - This code snippet creates a route for handling GET requests to the root URL ('/'). When a GET request is made to this endpoint, the server responds with "Hello, World!".

3. **Develop a route to handle POST requests in Express.js.**

   ```javascript
   app.post('/api/users', (req, res) => {
       // Logic to handle POST request
       res.send('User created successfully');
   });
   ```

   - This code snippet creates a route for handling POST requests to '/api/users'. When a POST request is made to this endpoint, the server responds with "User created successfully".

4. **Write a middleware function in Express.js to log incoming requests.**

   ```javascript
   app.use((req, res, next) => {
       console.log(`[${new Date().toLocaleString()}] ${req.method} ${req.url}`);
       next();
   });
   ```

   - This middleware function logs the timestamp, HTTP method, and URL of every incoming request.

5. **Implement error handling middleware in Express.js.**

   ```javascript
   app.use((err, req, res, next) => {
       console.error(err.stack);
       res.status(500).send('Internal Server Error');
   });
   ```

   - This middleware function catches errors that occur during request processing and sends a 500 status code along with an error message.

6. **Create a route to serve static files (e.g., HTML, CSS) in Express.js.**

   ```javascript
   app.use(express.static('public'));
   ```

   - This code snippet serves static files from the 'public' directory, allowing you to access files like HTML, CSS, and images directly from the server.

7. **Develop an endpoint to accept query parameters in Express.js.**

   ```javascript
   app.get('/search', (req, res) => {
       const query = req.query.q;
       res.send(`Search query: ${query}`);
   });
   ```

   - This code snippet creates a route for handling GET requests to '/search'. It retrieves the value of the 'q' query parameter from the request URL and sends it back as a response.

8. **Implement JWT authentication middleware in Express.js.**

   ```javascript
   const jwt = require('jsonwebtoken');

   const authenticateToken = (req, res, next) => {
       const authHeader = req.headers['authorization'];
       const token = authHeader && authHeader.split(' ')[1];
       if (token == null) return res.sendStatus(401);

       jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
           if (err) return res.sendStatus(403);
           req.user = user;
           next();
       });
   };

   app.get('/protected', authenticateToken, (req, res) => {
       res.send('Protected route');
   });
   ```

   - This middleware function verifies JWT tokens passed in the 'Authorization' header of incoming requests. It ensures that only authenticated users can access protected routes like '/protected'.

9. **Write a middleware function to parse request bodies in Express.js.**

   ```javascript
   app.use(express.json());
   ```

   - This middleware function parses JSON request bodies, making the request payload available as `req.body`.

10. **Develop a route to handle file uploads using Multer middleware in Express.js.**

    ```javascript
    const multer = require('multer');
    const upload = multer({ dest: 'uploads/' });

    app.post('/upload', upload.single('file'), (req, res) => {
        // Logic to handle file upload
        res.send('File uploaded successfully');
    });
    ```

    Certainly! Here are the answers for the next 10 questions:

11. **Implement pagination for database queries in Express.js.**

    ```javascript
    app.get('/products', (req, res) => {
        const page = req.query.page || 1;
        const pageSize = req.query.pageSize || 10;
        const startIndex = (page - 1) * pageSize;
        const endIndex = page * pageSize;

        const paginatedResults = results.slice(startIndex, endIndex);

        res.json(paginatedResults);
    });
    ```

    - This code snippet implements pagination for a list of products. It retrieves the page number and page size from query parameters and returns a subset of products based on the pagination parameters.

12. **Create a route to authenticate users using Passport.js in Express.js.**

    ```javascript
    const passport = require('passport');

    app.post('/login', passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/login',
        failureFlash: true
    }));
    ```

    - This code snippet creates a route for handling POST requests to '/login' using Passport.js for authentication. It redirects users to the dashboard on successful authentication or back to the login page on failure.

13. **Develop a route to handle user registration in Express.js.**

    ```javascript
    app.post('/register', (req, res) => {
        // Logic to register a new user
        res.send('User registered successfully');
    });
    ```

    - This code snippet creates a route for handling POST requests to '/register', where users can register by providing their details in the request body.

14. **Write middleware to hash passwords before storing them in Express.js.**

    ```javascript
    const bcrypt = require('bcrypt');

    const hashPassword = async (req, res, next) => {
        const salt = await bcrypt.genSalt(10);
        req.body.password = await bcrypt.hash(req.body.password, salt);
        next();
    };

    app.post('/register', hashPassword, (req, res) => {
        // Logic to save user with hashed password
        res.send('User registered successfully');
    });
    ```

    - This middleware function hashes the user's password before saving it to the database during user registration.

15. **Implement an endpoint to validate email addresses in Express.js.**

    ```javascript
    const validateEmail = (email) => {
        // Regular expression for email validation
        const emailRegex = /\S+@\S+\.\S+/;
        return emailRegex.test(email);
    };

    app.post('/validate-email', (req, res) => {
        const { email } = req.body;
        const isValidEmail = validateEmail(email);
        res.json({ valid: isValidEmail });
    });
    ```

    - This code snippet creates an endpoint to validate email addresses sent in the request body using a regular expression.

16. **Create a route to handle user login and issue JWT tokens in Express.js.**

    ```javascript
    const jwt = require('jsonwebtoken');

    app.post('/login', (req, res) => {
        const { username, password } = req.body;
        // Logic to authenticate user
        if (authenticated) {
            const accessToken = jwt.sign({ username }, process.env.ACCESS_TOKEN_SECRET);
            res.json({ accessToken });
        } else {
            res.status(401).send('Invalid username or password');
        }
    });
    ```

    - This code snippet creates a route for handling user login requests. Upon successful authentication, it issues a JWT token containing the username.

17. **Develop a middleware to perform role-based access control in Express.js.**

    ```javascript
    const roleAuthorization = (roles) => (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).send('Unauthorized');
        }
        next();
    };

    app.get('/admin', roleAuthorization(['admin']), (req, res) => {
        res.send('Admin dashboard');
    });
    ```

    - This middleware function checks if the authenticated user has the required role to access a particular route.

18. **Write a route to fetch data from a MongoDB database in Express.js.**

    ```javascript
    const mongoose = require('mongoose');
    const Product = mongoose.model('Product');

    app.get('/products', async (req, res) => {
        const products = await Product.find();
        res.json(products);
    });
    ```

    - This code snippet fetches data from a MongoDB database using Mongoose and returns the products as JSON.

19. **Implement sorting functionality for database queries in Express.js.**

    ```javascript
    app.get('/products', async (req, res) => {
        const sortBy = req.query.sortBy || 'name';
        const sortOrder = req.query.sortOrder || 'asc';

        const products = await Product.find().sort({ [sortBy]: sortOrder });
        res.json(products);
    });
    ```
    Develop an endpoint to send emails using Nodemailer in Express.js.

javascript
Copy code
const nodemailer = require('nodemailer');

app.post('/send-email', async (req, res) => {
    const { to, subject, text } = req.body;

    const transporter = nodemailer.createTransport({
        // Configure transporter options (e.g., SMTP)
    });

    const info = await transporter.sendMail({
        from: 'your-email@example.com',
        to,
        subject,
        text
    });

    res.json({ messageId: info.messageId });
});
This code snippet creates a route for sending emails using Nodemailer. It accepts recipient, subject, and message body from the request body

    

Sure, let's continue with the next 20 questions:

21. **Write middleware to authenticate users based on JWT tokens in Express.js.**

    ```javascript
    const jwt = require('jsonwebtoken');

    const authenticateToken = (req, res, next) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (token == null) return res.sendStatus(401);

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
            if (err) return res.sendStatus(403);
            req.user = user;
            next();
        });
    };

    app.get('/protected-route', authenticateToken, (req, res) => {
        res.send('You are authorized to access this route');
    });
    ```

    - This middleware function verifies JWT tokens passed in the 'Authorization' header of incoming requests. If the token is valid, it proceeds to the next middleware; otherwise, it sends a 403 Forbidden status.

22. **Implement a route to handle password reset requests in Express.js.**

    ```javascript
    app.post('/reset-password', (req, res) => {
        const { email } = req.body;
        // Logic to send password reset email
        res.send('Password reset email sent successfully');
    });
    ```

    - This code snippet creates a route for handling POST requests to '/reset-password'. It accepts the user's email and sends a password reset email to the user.

23. **Develop middleware for session management using express-session in Express.js applications.**

    ```javascript
    const session = require('express-session');

    app.use(session({
        secret: 'your-secret-key',
        resave: false,
        saveUninitialized: false
    }));
    ```

    - This middleware initializes session management using express-session. It configures session options such as a secret key and prevents saving uninitialized sessions.

24. **Implement an endpoint to delete user accounts in Express.js.**

    ```javascript
    app.delete('/delete-account', (req, res) => {
        const { userId } = req.user;
        // Logic to delete user account
        res.send('User account deleted successfully');
    });
    ```

    - This code snippet creates a route for handling DELETE requests to '/delete-account'. It extracts user ID from the JWT token and deletes the corresponding user account.

25. **Write middleware to restrict access to authenticated users in Express.js.**

    ```javascript
    const authenticateUser = (req, res, next) => {
        if (!req.user) {
            return res.status(401).send('Unauthorized');
        }
        next();
    };

    app.get('/protected-route', authenticateUser, (req, res) => {
        res.send('You are authorized to access this route');
    });
    ```

    - This middleware function checks if a user is authenticated by verifying the presence of a user object in the request. If the user is authenticated, it proceeds to the next middleware; otherwise, it sends a 401 Unauthorized status.

26. **Create a route to retrieve user data based on query parameters in Express.js.**

    ```javascript
    app.get('/user', (req, res) => {
        const { userId } = req.query;
        // Logic to fetch user data based on userId
        res.send(`User data for user ID ${userId}`);
    });
    ```

    - This code snippet creates a route for handling GET requests to '/user'. It retrieves user data based on the 'userId' query parameter.

27. **Implement rate limiting middleware to prevent abuse in Express.js.**

    ```javascript
    const rateLimit = require('express-rate-limit');

    const limiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100 // limit each IP to 100 requests per windowMs
    });

    app.use('/api/', limiter);
    ```

    - This middleware function implements rate limiting using the express-rate-limit package. It limits the number of requests per IP address to prevent abuse.

28. **Develop an endpoint to generate and send PDF files in Express.js.**

    ```javascript
    const pdfkit = require('pdfkit');
    const fs = require('fs');

    app.get('/generate-pdf', (req, res) => {
        const doc = new pdfkit();
        doc.pipe(fs.createWriteStream('output.pdf'));
        doc.text('Hello, World!');
        doc.end();
        res.send('PDF generated successfully');
    });
    ```

    - This code snippet creates a route for generating and sending PDF files using the pdfkit library.

29. **Write middleware to compress response bodies in Express.js.**

    ```javascript
    const compression = require('compression');

    app.use(compression());
    ```

    - This middleware function enables response compression using the compression middleware, reducing the size of response bodies for faster transmission.

30. **Create a route to handle image resizing using Sharp in Express.js.**

    ```javascript
    const sharp = require('sharp');

    app.get('/resize-image', (req, res) => {
        sharp('input.jpg')
            .resize(200, 300)
            .toFile('output.jpg', (err, info) => {
                if (err) {
                    console.error(err);
                    res.status(500).send('Internal Server Error');
                } else {
                    res.send('Image resized successfully');
                }
            });
    });
    ```

    - This code snippet creates a route for resizing images using the Sharp library. It resizes an input image to 200x300 pixels and saves the resized image as 'output.jpg'.

Certainly! Let's continue with the next set of 10 questions:

31. **Implement a route to handle file downloads in Express.js.**

    ```javascript
    app.get('/download', (req, res) => {
        const filePath = 'path/to/file';
        res.download(filePath);
    });
    ```

    - This code snippet creates a route for handling file downloads. It sends the file specified by the 'filePath' to the client for download.

32. **Develop middleware to handle CORS (Cross-Origin Resource Sharing) in Express.js.**

    ```javascript
    const cors = require('cors');

    app.use(cors());
    ```

    - This middleware function enables Cross-Origin Resource Sharing (CORS) in Express.js applications, allowing controlled access to resources from other origins.

33. **Create a route to handle user authentication with OAuth2 in Express.js.**

    ```javascript
    const passport = require('passport');

    app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

    app.get('/auth/google/callback',
        passport.authenticate('google', { failureRedirect: '/login' }),
        (req, res) => {
            // Successful authentication, redirect home.
            res.redirect('/');
        });
    ```

    - This code snippet creates routes for initiating and handling OAuth2 authentication with Google using Passport.js.

34. **Implement a route to handle WebSocket connections in Express.js.**

    ```javascript
    const WebSocket = require('ws');
    const wss = new WebSocket.Server({ port: 8080 });

    wss.on('connection', (ws) => {
        ws.on('message', (message) => {
            console.log(`Received message: ${message}`);
        });
    });
    ```

    - This code snippet creates a WebSocket server using the 'ws' library and listens for incoming WebSocket connections on port 8080.

35. **Write middleware to parse cookies in Express.js.**

    ```javascript
    const cookieParser = require('cookie-parser');

    app.use(cookieParser());
    ```

    - This middleware function parses cookies attached to incoming requests and makes them available in the 'req.cookies' object.

36. **Develop an endpoint to serve server-sent events (SSE) in Express.js.**

    ```javascript
    app.get('/events', (req, res) => {
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        
        // Send SSE data
        res.write('data: Hello\n\n');
    });
    ```

    - This code snippet creates a route for serving server-sent events (SSE) in Express.js, which enables servers to push updates to clients over HTTP connections.

37. **Implement a route to handle XML requests and responses in Express.js.**

    ```javascript
    const xmlparser = require('express-xml-bodyparser');

    app.use(xmlparser());

    app.post('/xml', (req, res) => {
        console.log(req.body);
        res.send('XML received');
    });
    ```

    - This code snippet demonstrates handling XML requests and responses in Express.js using the 'express-xml-bodyparser' middleware.

38. **Create middleware to authenticate users using Basic Authentication in Express.js.**

    ```javascript
    const basicAuth = require('express-basic-auth');

    app.use(basicAuth({
        users: { 'username': 'password' },
        unauthorizedResponse: 'Unauthorized'
    }));
    ```

    - This middleware function implements Basic Authentication in Express.js, requiring users to provide a username and password to access protected routes.

39. **Develop a route to handle server-sent events (SSE) with authentication in Express.js.**

    ```javascript
    app.get('/events', (req, res) => {
        if (!req.headers.authorization || req.headers.authorization !== 'Bearer token') {
            res.status(401).send('Unauthorized');
            return;
        }

        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');

        // Send SSE data
        res.write('data: Hello\n\n');
    });
    ```

    - This code snippet creates a route for serving server-sent events (SSE) with authentication in Express.js, requiring clients to provide a valid token in the 'Authorization' header.

40. **Write middleware to parse and validate JSON Web Tokens (JWT) in Express.js.**

    ```javascript
    const jwt = require('jsonwebtoken');

    const verifyToken = (req, res, next) => {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).send('Unauthorized');

        jwt.verify(token, 'secret', (err, decoded) => {
            if (err) return res.status(403).send('Forbidden');
            req.user = decoded;
            next();
        });
    };

    app.use('/protected', verifyToken);
    ```

    - This middleware function parses JWT tokens from the 'Authorization' header of incoming requests and verifies their authenticity, ensuring only authenticated users can access protected routes.



41. **Implement a route to handle file downloads in Express.js.**

    ```javascript
    app.get('/download', (req, res) => {
        const filePath = '/path/to/file.txt';
        res.download(filePath);
    });
    ```

    - This code snippet creates a route for downloading files. It uses the `res.download()` method to send a file as an attachment to the client.

42. **Develop middleware to sanitize input data in Express.js.**

    ```javascript
    const sanitize = require('sanitize-html');

    const sanitizeInput = (req, res, next) => {
        req.body = sanitize(req.body);
        next();
    };

    app.use(sanitizeInput);
    ```

    - This middleware function uses the sanitize-html library to sanitize input data, removing any potentially harmful HTML or script tags.

43. **Create a route to handle WebSocket connections in Express.js.**

    ```javascript
    const WebSocket = require('ws');

    const wss = new WebSocket.Server({ server });

    wss.on('connection', (ws) => {
        ws.on('message', (message) => {
            console.log(`Received message: ${message}`);
        });
        ws.send('Connected to WebSocket server');
    });
    ```

    - This code snippet sets up a WebSocket server using the ws library and handles incoming connections. It also logs received messages and sends a confirmation message to clients upon connection.

44. **Implement a route to handle JSON Web Token (JWT) refresh in Express.js.**

    ```javascript
    const jwt = require('jsonwebtoken');

    app.post('/refresh-token', (req, res) => {
        const refreshToken = req.body.refreshToken;

        // Verify refresh token and generate new access token
        // ...
    });
    ```

    - This code snippet creates a route for handling token refresh requests. It extracts the refresh token from the request body and generates a new access token if the refresh token is valid.

45. **Develop middleware to log request and response data in Express.js.**

    ```javascript
    const logger = (req, res, next) => {
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
        res.on('finish', () => {
            console.log(`[${new Date().toISOString()}] ${res.statusCode} ${res.statusMessage}`);
        });
        next();
    };

    app.use(logger);
    ```

    - This middleware function logs request and response data, including timestamps, HTTP method, URL, status code, and status message.

46. **Create a route to handle multipart form data in Express.js.**

    ```javascript
    const multer = require('multer');
    const upload = multer({ dest: 'uploads/' });

    app.post('/upload', upload.single('file'), (req, res) => {
        // Handle uploaded file
    });
    ```

    - This code snippet sets up a route for handling multipart form data uploads using the multer middleware.

47. **Implement a route to handle user authentication with Passport.js in Express.js.**

    ```javascript
    const passport = require('passport');

    app.post('/login', passport.authenticate('local', { session: false }), (req, res) => {
        // Handle successful authentication
    });
    ```

    - This code snippet creates a route for user authentication using Passport.js with the local strategy.

48. **Develop middleware to prevent CSRF attacks in Express.js.**

    ```javascript
    const csrf = require('csurf');
    const csrfProtection = csrf({ cookie: true });

    app.use(csrfProtection);
    ```

    - This middleware function protects against Cross-Site Request Forgery (CSRF) attacks by generating and validating CSRF tokens.

49. **Create a route to handle GraphQL queries in Express.js.**

    ```javascript
    const { graphqlHTTP } = require('express-graphql');
    const schema = require('./schema');

    app.use('/graphql', graphqlHTTP({
        schema,
        graphiql: true
    }));
    ```

    - This code snippet sets up a route for handling GraphQL queries using the express-graphql middleware and provides a graphical interface for testing queries.

50. **Implement a route to handle user logout in Express.js.**

    ```javascript
    app.get('/logout', (req, res) => {
        req.logout();
        res.redirect('/');
    });
    ```

    - This code snippet creates a route for user logout, which logs the user out of the session and redirects them to the homepage.

 
