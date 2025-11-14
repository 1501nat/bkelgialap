import { useState, useEffect } from "react";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "@/contexts/AuthContext";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import { Navbar } from "@/components/layout/Navbar";
import Home from "./pages/Home";
import Auth from "./pages/Auth";
import Dashboard from "./pages/Dashboard";
import Admin from "./pages/Admin";
import Courses from "./pages/Courses";
import Users from "./pages/Users";
import Profile from "./pages/Profile";
import Assignments from "./pages/Assignments";
import Attendance from "./pages/Attendance";
import Announcements from "./pages/Announcements";
import Enrollments from "./pages/Enrollments";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const Layout = ({ children, darkMode, toggleDarkMode }: any) => (
  <div className={darkMode ? "dark" : ""}>
    <Navbar darkMode={darkMode} toggleDarkMode={toggleDarkMode} />
    <main className="min-h-[calc(100vh-4rem)]">{children}</main>
  </div>
);

const App = () => {
  const [darkMode, setDarkMode] = useState(false);
  
  useEffect(() => {
    const saved = localStorage.getItem("darkMode");
    if (saved) setDarkMode(JSON.parse(saved));
  }, []);

  useEffect(() => {
    localStorage.setItem("darkMode", JSON.stringify(darkMode));
  }, [darkMode]);

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <AuthProvider>
            <Routes>
              <Route path="/auth" element={<Auth />} />
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <Layout darkMode={darkMode} toggleDarkMode={() => setDarkMode(!darkMode)}>
                      <Home />
                    </Layout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/dashboard"
                element={
                  <ProtectedRoute>
                    <Layout darkMode={darkMode} toggleDarkMode={() => setDarkMode(!darkMode)}>
                      <Dashboard />
                    </Layout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/admin"
                element={
                  <ProtectedRoute allowedRoles={['admin']}>
                    <Layout darkMode={darkMode} toggleDarkMode={() => setDarkMode(!darkMode)}>
                      <Admin />
                    </Layout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/courses"
                element={
                  <ProtectedRoute>
                    <Layout darkMode={darkMode} toggleDarkMode={() => setDarkMode(!darkMode)}>
                      <Courses />
                    </Layout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/users"
                element={
                  <ProtectedRoute allowedRoles={['admin']}>
                    <Layout darkMode={darkMode} toggleDarkMode={() => setDarkMode(!darkMode)}>
                      <Users />
                    </Layout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/profile"
                element={
                  <ProtectedRoute>
                    <Layout darkMode={darkMode} toggleDarkMode={() => setDarkMode(!darkMode)}>
                      <Profile />
                    </Layout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/assignments"
                element={
                  <ProtectedRoute>
                    <Layout darkMode={darkMode} toggleDarkMode={() => setDarkMode(!darkMode)}>
                      <Assignments />
                    </Layout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/attendance"
                element={
                  <ProtectedRoute>
                    <Layout darkMode={darkMode} toggleDarkMode={() => setDarkMode(!darkMode)}>
                      <Attendance />
                    </Layout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/announcements"
                element={
                  <ProtectedRoute>
                    <Layout darkMode={darkMode} toggleDarkMode={() => setDarkMode(!darkMode)}>
                      <Announcements />
                    </Layout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/enrollments"
                element={
                  <ProtectedRoute allowedRoles={['admin', 'lecturer']}>
                    <Layout darkMode={darkMode} toggleDarkMode={() => setDarkMode(!darkMode)}>
                      <Enrollments />
                    </Layout>
                  </ProtectedRoute>
                }
              />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </AuthProvider>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  );
};

export default App;
