-- Fix PUBLIC_DATA_EXPOSURE: Restrict profiles table access
-- Drop the overly permissive policy
DROP POLICY IF EXISTS "Users can view all profiles" ON public.profiles;

-- Allow users to view their own profile
CREATE POLICY "Users can view own profile" ON public.profiles
  FOR SELECT 
  USING (auth.uid() = id);

-- Allow lecturers to view profiles of students enrolled in their courses
CREATE POLICY "Lecturers can view enrolled student profiles" ON public.profiles
  FOR SELECT 
  USING (
    has_role(auth.uid(), 'lecturer'::app_role) AND
    EXISTS (
      SELECT 1 FROM enrollments e
      JOIN courses c ON e.course_id = c.id
      WHERE c.lecturer_id = auth.uid()
      AND e.student_id = profiles.id
    )
  );

-- Allow admins to view all profiles
CREATE POLICY "Admins can view all profiles" ON public.profiles
  FOR SELECT 
  USING (has_role(auth.uid(), 'admin'::app_role));