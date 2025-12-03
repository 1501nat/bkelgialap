-- Allow students to update their own enrollment status (for withdrawal requests)
CREATE POLICY "Students can update own enrollments"
ON public.enrollments
FOR UPDATE
USING (student_id = auth.uid())
WITH CHECK (student_id = auth.uid());