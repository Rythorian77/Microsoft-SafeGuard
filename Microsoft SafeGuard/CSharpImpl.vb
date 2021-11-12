Public Class CSharpImpl

    <Obsolete("Please refactor calling code to use normal Visual Basic assignment")>
    Shared Function Assign(Of T)(ByRef target As T,
                                 value As T) As T
        target = value
        Return value
    End Function

End Class