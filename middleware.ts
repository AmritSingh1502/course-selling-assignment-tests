import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

declare global {
    namespace Express {
        interface Request {
            userId?: string;
            role?: "STUDENT" | "INSTRUCTOR";
        }
    }
}

//auth middleware
export const authMiddleware = (req: Request , res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if(!authHeader){
        res.status(401).json({error: "No token provided"})
        return;
    }

    const token = authHeader.split(" ")[1];

    if(!token){
        res.status(401).json({error : " Token missing"});
        return;
    }


    try{
        const payload = jwt.verify(token, process.env.JWT_SECRET as string) as any;
        req.userId = payload.userId;
        req.role =payload.role;
        next();
    }catch(e){
        res.status(403).json({error: "Invalid token or expired token"});
    }
};

// role guard middleware
export const requireRole = (role: "STUDENT" | "INSTRUCTOR") => {
    return (req : Request, res: Response, next: NextFunction)=> {
        if(req.role !== role){
            res.status(403).json({error: `Access denied. Requires ${role} role.`});
            return;
        }
        next();
    };
};

// global error middleware
export const errorHandler = (err: any, req : Request, res: Response , next: NextFunction) => {
    console.error(err);
    res.status(err.statusCode || 500).json({
        error: err.message || "Internal Server Error",
        statusCode : err.statusCode || 500,
        timestamp : new Date().toString()
    });
};