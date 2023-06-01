from django import forms

class UserForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={'class':'form-control'}))
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class':'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control'}))
    password_repeat = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control'}))
    first_name = forms.CharField(widget=forms.TextInput(attrs={'class':'form-control'}))
    last_name = forms.CharField(widget=forms.TextInput(attrs={'class':'form-control'}))
    phone_number = forms.CharField(widget=forms.NumberInput(attrs={'class':'form-control'}), required=False)

class ChangePwdForm(forms.Form):
    existing_password = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control'}))
    new_password = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control'}))
    verify_password = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control'}))

class ForgotPwdForm(forms.Form):
    email_address = forms.EmailField(widget=forms.EmailInput(attrs={'class':'form-control'}))

class VerifyCodeForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={'class':'form-control'}))
    reset_code = forms.CharField(widget=forms.TextInput(attrs={'class':'form-control'}))

class ResetPwdForm(forms.Form):
    new_password = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control'}))
    verify_password = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control'}))