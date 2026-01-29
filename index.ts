import express from "express";
import { prisma } from "./db";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { CreateCourseSchema, CreateLessonSchema, LoginSchema, PurchaseCourseSchema, SignupSchema } from "./schemas";
import { authMiddleware, errorHandler, requireRole } from "./middleware";



const app = express();
app.use(express.json());

const SECRET = process.env.JWT_SECREAT!;

app.get("/me", authMiddleware, async (req, res, next) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
    });

    if (!user) {
      res.status(404).json({ error: "User not found" });
      return;
    }
    
    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role
    });
  } catch (error) {
    next(error);
  }
});

// auth endpoints

app.post("/auth/signup", async (req, res, next) => {
    try{
        const parsed  = SignupSchema.parse(req.body);
        const hassedPassword = await bcrypt.hash(parsed.password, 10);

        const user = await prisma.user.create({
            data: {
                email: parsed.email,
                password: hassedPassword,
                name: parsed.name,
                role: parsed.role,
            },
        });

        const token = jwt.sign({userId: user.id , role: user.role }, process.env.JWT_SECRET!);

        res.json({message: "User created",token , id: user.id});
    }catch(error) {
        next(error);
    }
});

app.post("/auth/login", async (req, res, next) => {
    try{
        const { email, password } = LoginSchema.parse(req.body);
        const user = await prisma.user.findUnique({where: {email}});

        if(!user || !(await bcrypt.compare(password, user.password))) {
            res.status(401).json({ error : "Invalid credentials"});
            return;
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if(!validPassword){
            res.status(403).json({error: "Invalid credentials"});
            return;
        }

        const token = jwt.sign({userId: user.id , role: user.role }, process.env.JWT_SECRET!);
        res.json({ token , id: user.id});
    }catch(error) {
        next(error);
    }
});



//course endpoints
// create only INSTRUCTOR
app.post("/courses", authMiddleware, requireRole("INSTRUCTOR"), async ( req, res, next) => {
    try{
        const parsed = CreateCourseSchema.parse(req.body);
        const course = await prisma.course.create({
            data: {
                ...parsed,
                instructorId:req.userId!,
            },
        });
        res.json(course);
    }catch(error){
        next(error);
    }
});

// get all courses
app.get("/courses", async (req, res,next) => {
    try{
        const courses = await prisma.course.findMany();
        res.json(courses);
    }catch(error){
        next(error);
    }
});

// get course by id
app.get("/courses/:id", async (req , res, next) => {
    try{
        const course = await prisma.course.findUnique({
            where : { id : req.params.id },
            include: { lessons: true },
        });

        if(!course){
            res.status(404).json({error : "Course not found"});
            return;
        }

        res.json(course);
    }catch(error){
        next(error);
    }
});

// update course only INSTRUCTOR

app.patch("/courses/:id", authMiddleware, requireRole("INSTRUCTOR"), async (req , res, next) => {
    try{
        const course = await prisma.course.findUnique({
            where: { id: req.params.id as string }
        });
        if(!course || course.instructorId != req.userId){
            res.status(403).json({error : "Not authorized to update the course"});
            return;
        }

        const updated = await prisma.course.update({
            where: {id : req.params.id as string},
            data : req.body
        });

        res.json(updated);
    }catch(error){
        next(error);
    }
});

// delete the course only INSTRUCTOR

app.delete("/courses/:id", authMiddleware, requireRole("INSTRUCTOR"), async (req,res,next) =>{
    try{
        const course = await prisma.course.findUnique({
            where: {id : req.params.id as string}
        });

        if(!course || course.instructorId != req.userId){
            res.status(403).json({error : " Not authorized to delete this course"});
            return;
        }

        await prisma.course.delete({
            where : {id : req.params.id as string}
        });
        res.json({message : "Course deleted"});
    }catch(error){
        next(error);
    }
});


// lesson endpoints

// only instructor of the course
app.post("/lessons", authMiddleware, requireRole("INSTRUCTOR"), async (req, res,next) => {
    try{
        const parsed = CreateLessonSchema.parse(req.body);

        const course = await prisma.course.findUnique({where: {id : parsed.courseId}});
        if(!course || course.instructorId != req.userId) {
            res.status(403).json({error : "You do not own this course"});
            return;
        }

        const lesson = await prisma.lesson.create({
            data: {
                title: parsed.title,
                content: parsed.content,
                courseId: parsed.courseId
            }
        });
        res.json(lesson);
    }catch(error){
        next(error);
    }
});


// get the lesson
app.get("/courses/:courseId/lessons", async (req, res, next) =>{
    try{
        const lessons = await prisma.lesson.findMany({
            where: { courseId : req.params.courseId}
        });
        res.json(lessons);
    }catch(error){
        next(error);
    }
});


// purchase endpoint

app.post("/purchases", authMiddleware, requireRole("STUDENT"), async (req, res,next)=> {
    try{
        const { courseId } = PurchaseCourseSchema.parse(req.body);

        const course = await prisma.course.findUnique({
            where: {id: courseId}
        });
        if(!course){
            res.status(404).json({error: "Course not found"});
            return;
        }

        const existing = await prisma.purchase.findFirst({
            where : { userId: req.userId!, courseId: courseId}
        });

        if(existing){
            res.status(409).json({message: "Course already pruchased"});
            return;
        }

        const purchase  = await prisma.purchase.create({
            data: {
                userId : req.userId!, courseId
            }
        });

        res.json({message: "Course purchased successfully", purchaseId: purchase.id});

    }catch (error){
        next(error);
    }
});

// get purchases courses for user
app.get("/users/:id/purchases", authMiddleware, async (req, res, next) => {
    try{
        const { id } = req.params;
        if(id !== req.userId){
            res.status(403).json({error: "Access denied"});
            return;
        }

        const purchases = await prisma.purchase.findMany({
            where : {userId : id},
            include : {course: true}
        });
        res.json(purchases);
    }catch(error){
        next(error);
    }
})



app.use(errorHandler);

const PORT = process.env.PORT!;
app.listen(PORT, ()=> {
    console.log(`Server runnning on port ${PORT}`);
})

