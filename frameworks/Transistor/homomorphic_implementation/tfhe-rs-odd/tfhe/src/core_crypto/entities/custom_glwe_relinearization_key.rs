//! Module containing the definition of the [`RelinearizationKey`].

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::glwe_ciphertext::glwe_ciphertext_size;
use crate::core_crypto::entities::glwe_ciphertext_list::{
    GlweCiphertextListCreationMetadata, GlweCiphertextListMutView, GlweCiphertextListView,
};

/// A keyswitching key allowing to relinearize [`a GLWE ciphertext`](super::GlweCiphertext) to
/// [`a GLWE ciphertext`](super::GlweCiphertext) after a tensor ptoduct.
/// 
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RelinearizationKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    input_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for RelinearizationKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for RelinearizationKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in an encryption of an input product of two [`super::GlweSecretKey`] element for a
/// [`RelinearizationKey`] given a [`DecompositionLevelCount`] and output [`GlweSize`] and
/// [`PolynomialSize`].
pub fn relinearization_key_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
) -> usize {
    // One ciphertext per level encrypted under the output key
    decomp_level_count.0 * glwe_ciphertext_size(output_glwe_size, output_polynomial_size)
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> RelinearizationKey<C> {
    /// Create an [`RelinearizationKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`RelinearizationKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_relinearization_key`] using this key as
    /// output.
    ///
    /// This docstring exhibits [`RelinearizationKey`] primitives usage.
    ///
    ///TODO : adapter la version de LwepackingKey
    /// ```
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an RelinearizationKey"
        );
        assert!(
            container.container_len()
                % relinearization_key_input_key_element_encrypted_size(
                    decomp_level_count,
                    output_glwe_size,
                    output_polynomial_size
                )
                == 0,
            "The provided container length is not valid. \
        It needs to be dividable by: {}. Got container length: {} and decomp_level_count: \
        {decomp_level_count:?}, output_glwe_size: {output_glwe_size:?}, output_polynomial_size: \
        {output_polynomial_size:?}.",
            relinearization_key_input_key_element_encrypted_size(
                decomp_level_count,
                output_glwe_size,
                output_polynomial_size
            ),
            container.container_len()
        );

        Self {
            data: container,
            decomp_base_log,
            decomp_level_count,
            input_glwe_size: output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        }
    }

    /// Return the [`DecompositionBaseLog`] of the [`RelinearizationKey`].
    ///
    /// See [`RelinearizationKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`RelinearizationKey`].
    ///
    /// See [`RelinearizationKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }


    /// Return the input [`GlweDimension`] of the [`RelinearizationKey`].
    ///
    /// See [`RelinearizationKey::from_container`] for usage.
    pub fn input_key_glwe_dimension(&self) -> GlweDimension {
        self.input_glwe_size.to_glwe_dimension()
    }

    /// Return the output [`PolynomialSize`] of the [`RelinearizationKey`].
    ///
    /// See [`RelinearizationKey::from_container`] for usage.
    pub fn output_key_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    /// Return the output [`GlweSize`] of the [`RelinearizationKey`].
    ///
    /// See [`RelinearizationKey::from_container`] for usage.
    pub fn output_glwe_size(&self) -> GlweSize {
        self.input_glwe_size
    }

    /// Return the output [`PolynomialSize`] of the [`RelinearizationKey`].
    ///
    /// See [`RelinearizationKey::from_container`] for usage.
    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    /// Return the number of elements in an encryption of an input [`super::LweSecretKey`] element
    /// of the current [`RelinearizationKey`].
    pub fn input_key_element_encrypted_size(&self) -> usize {
        relinearization_key_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.input_glwe_size,
            self.output_polynomial_size,
        )
    }

    /// Return a view of the [`RelinearizationKey`]. This is useful if an algorithm takes a view
    /// by value.
    pub fn as_view(&self) -> RelinearizationKeyView<'_, Scalar> {
        RelinearizationKey::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.input_glwe_size,
            self.output_polynomial_size,
            self.ciphertext_modulus,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`RelinearizationKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_glwe_ciphertext_list(&self) -> GlweCiphertextListView<'_, Scalar> {
        GlweCiphertextListView::from_container(
            self.as_ref(),
            self.output_glwe_size(),
            self.output_polynomial_size(),
            self.ciphertext_modulus(),
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> RelinearizationKey<C> {
    /// Mutable variant of [`RelinearizationKey::as_view`].
    pub fn as_mut_view(&mut self) -> RelinearizationKeyMutView<'_, Scalar> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_glwe_size = self.input_glwe_size;
        let output_polynomial_size = self.output_polynomial_size;
        let ciphertext_modulus = self.ciphertext_modulus;
        RelinearizationKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_glwe_ciphertext_list(&mut self) -> GlweCiphertextListMutView<'_, Scalar> {
        let output_glwe_size = self.output_glwe_size();
        let output_polynomial_size = self.output_polynomial_size();
        let ciphertext_modulus = self.ciphertext_modulus();
        GlweCiphertextListMutView::from_container(
            self.as_mut(),
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        )
    }
}

/// An [`RelinearizationKey`] owning the memory for its own storage.
pub type RelinearizationKeyOwned<Scalar> = RelinearizationKey<Vec<Scalar>>;
/// An [`RelinearizationKey`] immutably borrowing memory for its own storage.
pub type RelinearizationKeyView<'data, Scalar> = RelinearizationKey<&'data [Scalar]>;
/// An [`RelinearizationKey`] mutably borrowing memory for its own storage.
pub type RelinearizationKeyMutView<'data, Scalar> = RelinearizationKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> RelinearizationKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`RelinearizationKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`RelinearizationKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_relinearization_key`] using this key as
    /// output.
    ///
    /// See [`RelinearizationKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_glwe_dimension: GlweDimension,
        output_key_polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                input_key_glwe_dimension.to_glwe_size().0 * (input_key_glwe_dimension.to_glwe_size().0 - 1) / 2     //glwe_size = k+1
                    * relinearization_key_input_key_element_encrypted_size(
                        decomp_level_count,
                        input_key_glwe_dimension.to_glwe_size(),
                        output_key_polynomial_size
                    )
            ],
            decomp_base_log,
            decomp_level_count,
            input_key_glwe_dimension.to_glwe_size(),
            output_key_polynomial_size,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for RelinearizationKey<C>
{
    type Element = C::Element;

    type EntityViewMetadata = GlweCiphertextListCreationMetadata<Self::Element>;

    type EntityView<'this> = GlweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    // At the moment it does not make sense to return "sub" keyswitch keys. So we use a dummy
    // placeholder type here.
    type SelfView<'this> = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        GlweCiphertextListCreationMetadata(
            self.output_glwe_size(),
            self.output_polynomial_size(),
            self.ciphertext_modulus(),
        )
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    /// Unimplemented for [`RelinearizationKey`]. At the moment it does not make sense to
    /// return "sub" keyswitch keys.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for RelinearizationKey. \
        At the moment it does not make sense to return 'sub' keyswitch keys."
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for RelinearizationKey<C>
{
    type EntityMutView<'this> = GlweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    // At the moment it does not make sense to return "sub" keyswitch keys. So we use a dummy
    // placeholder type here.
    type SelfMutView<'this> = DummyCreateFrom
    where
        Self: 'this;
}
