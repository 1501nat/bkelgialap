import { useState } from 'react';
import { motion } from 'framer-motion';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import { UserPlus } from 'lucide-react';

const Admin = () => {
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [role, setRole] = useState<'student' | 'lecturer' | 'admin'>('student');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (password.length < 8) {
      toast.error('Mật khẩu phải có ít nhất 8 ký tự');
      return;
    }
    
    setLoading(true);

    try {
      // Get current session token
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) {
        throw new Error('Bạn cần đăng nhập để thực hiện thao tác này');
      }

      // Call Edge Function to create user
      const { data, error } = await supabase.functions.invoke('admin-create-user', {
        body: { email, password, full_name: fullName, role }
      });

      if (error) throw error;
      if (data?.error) throw new Error(data.error);

      toast.success(`Đã tạo tài khoản ${email} với quyền ${role}`);
      setEmail('');
      setFullName('');
      setPassword('');
      setRole('student');
    } catch (error: any) {
      console.error('Create user error:', error);
      toast.error(error.message || 'Lỗi khi tạo người dùng');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container py-8 px-4">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <h1 className="text-3xl font-bold mb-2">Quản lý Hệ thống</h1>
        <p className="text-muted-foreground mb-8">Cấp email và quản lý người dùng</p>

        <Card className="max-w-2xl shadow-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <UserPlus className="h-5 w-5" />
              Tạo Tài khoản Mới
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleCreateUser} className="space-y-4">
              <div className="space-y-2">
                <Label>Email</Label>
                <Input
                  type="email"
                  placeholder="email@hcmut.edu.vn"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label>Họ và tên</Label>
                <Input
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label>Mật khẩu mặc định</Label>
                <Input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label>Vai trò</Label>
                <Select value={role} onValueChange={(v: any) => setRole(v)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="student">Sinh viên</SelectItem>
                    <SelectItem value="lecturer">Giảng viên</SelectItem>
                    <SelectItem value="admin">Admin</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Button type="submit" disabled={loading} className="w-full">
                {loading ? 'Đang tạo...' : 'Tạo Tài khoản'}
              </Button>
            </form>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
};

export default Admin;
