import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { ChevronDown, ChevronUp, User, ExternalLink } from 'lucide-react';

interface Submission {
  id: string;
  student_id: string;
  file_url: string | null;
  content: string | null;
  submitted_at: string | null;
  score: number | null;
  student_name?: string;
}

interface SubmissionsListProps {
  assignmentId: string;
}

const SubmissionsList = ({ assignmentId }: SubmissionsListProps) => {
  const [submissions, setSubmissions] = useState<Submission[]>([]);
  const [loading, setLoading] = useState(true);
  const [isOpen, setIsOpen] = useState(false);
  const [selectedSubmission, setSelectedSubmission] = useState<Submission | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);

  useEffect(() => {
    fetchSubmissions();
  }, [assignmentId]);

  const fetchSubmissions = async () => {
    try {
      const { data: submissionsData, error } = await supabase
        .from('submissions')
        .select('*')
        .eq('assignment_id', assignmentId)
        .order('submitted_at', { ascending: false });

      if (error) throw error;

      // Fetch student profiles
      const studentIds = submissionsData?.map(s => s.student_id) || [];
      if (studentIds.length > 0) {
        const { data: profiles } = await supabase
          .from('profiles')
          .select('id, full_name')
          .in('id', studentIds);

        const submissionsWithNames = submissionsData?.map(submission => ({
          ...submission,
          student_name: profiles?.find(p => p.id === submission.student_id)?.full_name || 'Không xác định'
        })) || [];

        setSubmissions(submissionsWithNames);
      } else {
        setSubmissions([]);
      }
    } catch (error) {
      console.error('Error fetching submissions:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString('vi-VN');
  };

  if (loading) {
    return <div className="text-sm text-muted-foreground">Đang tải...</div>;
  }

  if (submissions.length === 0) {
    return null;
  }

  return (
    <>
      <Collapsible open={isOpen} onOpenChange={setIsOpen} className="mt-4 pt-4 border-t">
        <CollapsibleTrigger asChild>
          <Button variant="ghost" size="sm" className="w-full justify-between">
            <span className="text-sm font-medium">
              Đã nộp: {submissions.length} sinh viên
            </span>
            {isOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent className="mt-2 space-y-1">
          {submissions.map((submission) => (
            <button
              key={submission.id}
              onClick={() => {
                setSelectedSubmission(submission);
                setDetailOpen(true);
              }}
              className="w-full flex items-center gap-2 p-2 rounded-md hover:bg-muted transition-colors text-left"
            >
              <User className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm flex-1">{submission.student_name}</span>
              <span className="text-xs text-muted-foreground">
                {formatDate(submission.submitted_at)}
              </span>
            </button>
          ))}
        </CollapsibleContent>
      </Collapsible>

      <Dialog open={detailOpen} onOpenChange={setDetailOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Chi tiết bài nộp - {selectedSubmission?.student_name}</DialogTitle>
          </DialogHeader>
          {selectedSubmission && (
            <div className="space-y-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Thời gian nộp</label>
                <p className="text-sm">{formatDate(selectedSubmission.submitted_at)}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Link bài tập</label>
                {selectedSubmission.file_url ? (
                  <a
                    href={selectedSubmission.file_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-primary hover:underline text-sm"
                  >
                    <ExternalLink className="h-4 w-4" />
                    {selectedSubmission.file_url}
                  </a>
                ) : (
                  <p className="text-sm text-muted-foreground">Không có</p>
                )}
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Ghi chú</label>
                <p className="text-sm whitespace-pre-wrap">
                  {selectedSubmission.content || 'Không có ghi chú'}
                </p>
              </div>
              {selectedSubmission.score !== null && (
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Điểm</label>
                  <p className="text-sm font-medium">{selectedSubmission.score}</p>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
};

export default SubmissionsList;
