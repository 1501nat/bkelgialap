-- Allow students to insert their own enrollments
CREATE POLICY "Students can insert own enrollments"
ON public.enrollments
FOR INSERT
WITH CHECK (student_id = auth.uid());

-- Allow lecturers to update enrollments for their courses (approve/reject)
CREATE POLICY "Lecturers can update course enrollments"
ON public.enrollments
FOR UPDATE
USING (EXISTS (
  SELECT 1 FROM courses
  WHERE courses.id = enrollments.course_id
  AND courses.lecturer_id = auth.uid()
));

-- Allow lecturers to delete enrollments for their courses
CREATE POLICY "Lecturers can delete course enrollments"
ON public.enrollments
FOR DELETE
USING (EXISTS (
  SELECT 1 FROM courses
  WHERE courses.id = enrollments.course_id
  AND courses.lecturer_id = auth.uid()
));