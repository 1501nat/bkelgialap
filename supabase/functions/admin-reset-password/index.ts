import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.80.0'
import { corsHeaders } from '../_shared/cors.ts'

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return new Response(
        JSON.stringify({ error: 'Không có authorization header' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Verify caller is authenticated and has admin role
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      { global: { headers: { Authorization: authHeader } } }
    )

    const { data: { user }, error: userError } = await supabaseClient.auth.getUser()
    if (userError || !user) {
      return new Response(
        JSON.stringify({ error: 'Unauthorized' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Check if caller has admin role
    const { data: roleData, error: roleError } = await supabaseClient
      .from('user_roles')
      .select('role')
      .eq('user_id', user.id)
      .single()

    if (roleError || roleData?.role !== 'admin') {
      return new Response(
        JSON.stringify({ error: 'Chỉ admin mới có quyền đặt lại mật khẩu' }),
        { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Parse request body
    const { user_id, new_password } = await req.json()

    // Validate input
    if (!user_id || !new_password) {
      return new Response(
        JSON.stringify({ error: 'Thiếu thông tin bắt buộc' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    if (new_password.length < 8) {
      return new Response(
        JSON.stringify({ error: 'Mật khẩu phải có ít nhất 8 ký tự' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Use service role client to reset password
    const adminClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    )

    // Reset user password
    const { data, error } = await adminClient.auth.admin.updateUserById(
      user_id,
      { password: new_password }
    )

    if (error) {
      console.error('Error resetting password:', error)
      return new Response(
        JSON.stringify({ error: error.message }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Store password in user_passwords table for admin viewing
    const { error: passwordStoreError } = await adminClient
      .from('user_passwords')
      .upsert({ 
        user_id: user_id,
        password: new_password,
        created_by: user.id,
        updated_at: new Date().toISOString()
      }, {
        onConflict: 'user_id'
      })

    if (passwordStoreError) {
      console.error('Error storing password:', passwordStoreError)
      // Don't fail the operation, password was already reset
    }

    return new Response(
      JSON.stringify({ 
        success: true, 
        message: 'Mật khẩu đã được đặt lại thành công',
        user: data.user 
      }),
      { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
  } catch (error) {
    console.error('Unexpected error:', error)
    const errorMessage = error instanceof Error ? error.message : 'Đã xảy ra lỗi không xác định'
    return new Response(
      JSON.stringify({ error: errorMessage }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
  }
})