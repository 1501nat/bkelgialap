import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import { Send, Edit } from 'lucide-react';

interface SubmissionFormProps {
  assignmentId: string;
  userId: string;
  existingSubmission?: {
    id: string;
    file_url: string | null;
    content: string | null;
  } | null;
  onSubmitSuccess: () => void;
}

const SubmissionForm = ({ assignmentId, userId, existingSubmission, onSubmitSuccess }: SubmissionFormProps) => {
  const [open, setOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formData, setFormData] = useState({
    file_url: existingSubmission?.file_url || '',
    content: existingSubmission?.content || ''
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!formData.file_url.trim()) {
      toast.error('Vui lòng nhập link bài tập');
      return;
    }

    setSubmitting(true);
    try {
      if (existingSubmission) {
        const { error } = await supabase
          .from('submissions')
          .update({
            file_url: formData.file_url,
            content: formData.content,
            submitted_at: new Date().toISOString()
          })
          .eq('id', existingSubmission.id);

        if (error) throw error;
        toast.success('Cập nhật bài nộp thành công');
      } else {
        const { error } = await supabase
          .from('submissions')
          .insert({
            assignment_id: assignmentId,
            student_id: userId,
            file_url: formData.file_url,
            content: formData.content
          });

        if (error) throw error;
        toast.success('Nộp bài tập thành công');
      }

      setOpen(false);
      onSubmitSuccess();
    } catch (error: any) {
      toast.error(error.message || 'Có lỗi xảy ra');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button 
          size="sm" 
          variant={existingSubmission ? "outline" : "default"}
          onClick={() => {
            setFormData({
              file_url: existingSubmission?.file_url || '',
              content: existingSubmission?.content || ''
            });
          }}
        >
          {existingSubmission ? (
            <>
              <Edit className="h-4 w-4 mr-1" />
              Chỉnh sửa
            </>
          ) : (
            <>
              <Send className="h-4 w-4 mr-1" />
              Nộp bài
            </>
          )}
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {existingSubmission ? 'Chỉnh sửa bài nộp' : 'Nộp bài tập'}
          </DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <Label htmlFor="submission_url">Link bài tập *</Label>
            <Input
              id="submission_url"
              type="url"
              placeholder="https://drive.google.com/..."
              value={formData.file_url}
              onChange={(e) => setFormData({ ...formData, file_url: e.target.value })}
              required
            />
          </div>
          <div>
            <Label htmlFor="submission_notes">Ghi chú</Label>
            <Textarea
              id="submission_notes"
              placeholder="Ghi chú thêm cho bài nộp..."
              value={formData.content}
              onChange={(e) => setFormData({ ...formData, content: e.target.value })}
              rows={3}
            />
          </div>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Hủy
            </Button>
            <Button type="submit" disabled={submitting}>
              {submitting ? 'Đang xử lý...' : existingSubmission ? 'Cập nhật' : 'Nộp bài'}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
};

export default SubmissionForm;
